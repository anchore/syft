package task

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/dustin/go-humanize"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

const ArchiveCatalogerTaskName = "archive-cataloger"

// NewArchiveCatalogerTask returns a task that recursively extracts archives (including JAR-family
// ones, whose cataloger skips its own unarchiving when this task is enabled), treats each as its own
// standalone indexed filesystem, runs subPipeline against each, and records file-level CONTAINS
// relationships from the archive to what was found inside it.
//
// Returns nil when archive cataloging is disabled (MaxDepth == 0; negative means unbounded).
//
// subPipeline must not include this task, so recursion is driven only by the depth-limited walk here.
// newStoreResolver is injected so this package does not depend on the internal fileresolver package.
func NewArchiveCatalogerTask(cfg cataloging.ArchiveSearchConfig, subPipeline []Task, newStoreResolver archive.StoreResolverFactory, notify archive.Notify) Task {
	if cfg.MaxDepth == 0 || newStoreResolver == nil {
		return nil
	}

	// this task drives recursion itself: in its own sub-pipeline, each nesting level would be processed
	// once by the walk and again by the nested copy
	subPipeline = withoutArchiveCataloger(subPipeline)
	if len(subPipeline) == 0 {
		return nil
	}
	fn := func(ctx context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		// this task re-runs catalogers, so it must ensure each keeps to one row; a scan installs the
		// registry up front, this covers a pipeline assembled without one
		ctx = bus.WithCatalogerTaskRegistry(ctx)

		// one progress row for the whole walk; the sub-pipeline's catalogers each report into the row
		// they already own (see bus.WithCatalogerTaskRegistry), not this one
		prog := bus.StartCatalogerTask(ctx, archiveCatalogerProgressInfo(), -1, "")
		c := &archiveCataloger{
			cfg:              cfg,
			subPipeline:      subPipeline,
			extractors:       archive.DefaultExtractors(),
			limiter:          archive.NewLimiter(archive.DefaultLimits(cfg)),
			newStoreResolver: newStoreResolver,
			notify:           notify,
			prog:             prog,
		}
		err := c.catalog(archive.WithLimiter(ctx, c.limiter), resolver, nil, 0, builder)
		c.left(nil)
		c.logStats()
		prog.SetCompleted()

		return err
	}
	return NewTask(ArchiveCatalogerTaskName, fn, pkgcataloging.PackageTag, "archive")
}

func archiveCatalogerProgressInfo() monitor.GenericTask {
	return monitor.GenericTask{
		Title: monitor.Title{
			Default:      "Archives",
			WhileRunning: "Cataloging archives",
			OnSuccess:    "Cataloged archives",
		},
		ID:       ArchiveCatalogerTaskName,
		ParentID: monitor.TopLevelCatalogingTaskID,
	}
}

func withoutArchiveCataloger(tasks []Task) []Task {
	out := make([]Task, 0, len(tasks))
	for _, t := range tasks {
		if t == nil {
			continue
		}
		if t.Name() == ArchiveCatalogerTaskName {
			log.WithFields("task", t.Name()).
				Debug("dropping archive cataloger task from its own sub-pipeline")
			continue
		}
		out = append(out, t)
	}
	return out
}

type archiveCataloger struct {
	cfg              cataloging.ArchiveSearchConfig
	subPipeline      []Task
	extractors       []archive.Extractor
	newStoreResolver archive.StoreResolverFactory

	// notify carries structured extraction events - which archive spilled to disk and why, which was
	// skipped. Nil is the no-op.
	notify archive.Notify

	// limiter measures the archive content held right now, falling as each archive is released. One
	// instance per task run, since one task run is one scan.
	limiter *archive.Limiter

	// prog is the single progress row for the whole walk: its count and stage are how many archives have
	// been entered, its context names the one being cataloged right now.
	prog *monitor.TaskProgress

	// slowest is the archive that spent the most time on its own extraction and cataloging, by virtual
	// path. Guarded because the walk runs alongside the top-level catalogers.
	statsMu      sync.Mutex
	slowest      time.Duration
	slowestPath  string
	archivesSeen int64
}

// recordArchiveTime keeps the longest self time seen and the archive that spent it. Self time
// excludes nested archives; inclusive time would name the outermost archive every run.
func (c *archiveCataloger) recordArchiveTime(virtualPath string, took time.Duration) {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	c.archivesSeen++
	if took > c.slowest {
		c.slowest = took
		c.slowestPath = virtualPath
	}
}

// logStats reports what the walk cost, once, when it is done. The peaks are high-water marks of the
// gauges the limits are enforced against - comparable to the configured bounds, not process memory or
// filesystem usage. One line per scan, so it logs at info; per-archive lines stay at debug.
func (c *archiveCataloger) logStats() {
	c.statsMu.Lock()
	slowest, slowestPath, seen := c.slowest, c.slowestPath, c.archivesSeen
	c.statsMu.Unlock()

	peakMemory, peakDisk := c.limiter.Peak()
	fields := []any{
		"archives", seen,
		"peak-memory", humanize.Bytes(uint64(peakMemory)),
		"peak-disk", humanize.Bytes(uint64(peakDisk)),
	}
	if slowestPath != "" {
		fields = append(fields, "slowest", slowestPath, "slowest-took", slowest.Round(time.Millisecond))
	}
	log.WithFields(fields...).Info("nested archive cataloging complete")
}

// catalog discovers archives in the given resolver and processes each, recursing up to MaxDepth.
// parent is the traversal for the archive being searched (nil at the scan root).
func (c *archiveCataloger) catalog(ctx context.Context, resolver file.Resolver, parent *archive.Traversal, depth int, builder sbomsync.Builder) error {
	if c.cfg.MaxDepth >= 0 && depth >= c.cfg.MaxDepth {
		return nil
	}

	var errs error
	for _, candidate := range c.discoverArchives(resolver) {
		// no between-archives check: a limit falls when an archive is released, so reaching a bound skips
		// only the archive that reached it
		if err := c.processArchive(ctx, resolver, candidate, parent, depth, builder); err != nil {
			errs = unknown.Append(errs, candidate.location, err)
		}
	}
	return errs
}

func (c *archiveCataloger) processArchive(ctx context.Context, parentResolver file.Resolver, candidate archiveCandidate, parent *archive.Traversal, depth int, builder sbomsync.Builder) error {
	archiveLoc := candidate.location
	content, err := parentResolver.FileContentsByLocation(archiveLoc)
	if err != nil {
		return err
	}
	defer internal.CloseAndLogError(content, archiveLoc.AccessPath)

	// check a non-sniffing candidate cheaply before reading it in full: an appended archive carries an
	// entry signature near the front, and almost nothing else does
	var archiveContent io.Reader = content
	if !candidate.sniffedAsArchive {
		var mayHide bool
		archiveContent, mayHide = archive.MayHideAnAppendedArchive(content)
		if !mayHide {
			return nil
		}
	}

	// self time: extraction, sub-pipeline and merge, stopped before the recursive descent so a
	// containing archive is not charged for what it contains
	started := time.Now()

	// extracted files inherit the filesystem id of where the archive was found (a layer digest for an
	// image source, empty for a directory source). The nesting chain rides separately as the archive
	// path, so same-named files in different archives - and the same archive path in different layers -
	// stay distinct in coordinate-keyed tables.
	archivePath := parent.VirtualPathOf(accessPath(archiveLoc))
	extracted, err := archive.ExtractToResolver(ctx, archiveContent, archiveLoc.AccessPath, archiveLoc.FileSystemID, archivePath, c.extractors, c.limiter, c.newStoreResolver, c.notify)
	if errors.Is(err, archive.ErrDiskLimitReached) {
		// terminal: nothing is released while this archive waits, so skip it and continue the scan
		log.WithFields("archive", accessPath(archiveLoc), "limit", c.cfg.MaxDiskBytes).
			Debug("skipping archive whose content would exceed the disk limit")
		return nil
	}
	if err != nil {
		return err
	}
	if extracted == nil {
		// nothing could open it: a format with no extractor (ar, a bare non-tar gzip), or a candidate
		// whose head only looked like it hid an archive. Logged rather than returned: an image can hold
		// thousands, and accumulating an error each into a chain later walked for coordinate errors is
		// quadratic. A corrupt archive does return an error.
		log.WithFields("archive", accessPath(archiveLoc), "sniffed-as-archive", candidate.sniffedAsArchive).
			Trace("no extractor could read this candidate; skipping")
		return nil
	}
	// releases the extraction directory and this archive's charges, after the sub-pipeline and recursion
	defer extracted.Cleanup()

	if extracted.Result.Truncated() {
		// catalog what was stored rather than discarding the archive, and record it in the SBOM's
		// unknowns as well as the log, since the packages found here are not the full set
		log.WithFields("archive", accessPath(archiveLoc), "limit", string(extracted.Result.Truncation)).
			Debug("archive extraction truncated by a configured limit; cataloging partial contents")

		appendUnknowns(builder, ArchiveCatalogerTaskName, []unknown.CoordinateError{{
			Coordinates: archiveLoc.Coordinates,
			Reason: fmt.Errorf("archive cataloged from part of its contents: extraction stopped at the %s",
				string(extracted.Result.Truncation)),
		}})
	}

	// expose the nesting chain to the sub-pipeline and deeper recursion, so catalogers can reconstruct
	// nesting-aware identity such as the java cataloger's colon-delimited virtual paths
	trav := &archive.Traversal{
		Location:    archiveLoc,
		VirtualPath: archivePath,
		Digests:     extracted.Digests,
	}
	subCtx := archive.WithTraversal(ctx, trav)

	c.entering()

	scratch := c.runSubPipeline(subCtx, extracted.Resolver, archiveLoc.Coordinates)

	mergeArchiveResults(archiveLoc.Coordinates, scratch, builder)

	c.left(trav)
	c.recordArchiveTime(trav.VirtualPath, time.Since(started))

	return c.catalog(subCtx, extracted.Resolver, trav, depth+1, builder)
}

// entering counts this archive onto the walk's single progress row; left takes the row's stage back
// once the archive is done, naming it unless the whole walk has finished. Both are nil-safe.
//
// The stage is reset because each sub-pipeline signs off with its own summary, which would otherwise
// stand while the next archive is extracted. The count of archives entered is always true.
func (c *archiveCataloger) entering() {
	if c.prog == nil {
		return
	}
	c.prog.Increment()
}

func (c *archiveCataloger) left(traversal *archive.Traversal) {
	if c.prog == nil {
		return
	}
	if traversal == nil {
		c.prog.AtomicStage.Set(fmt.Sprintf("%s archives", humanize.Comma(c.prog.Current())))
	} else {
		c.prog.AtomicStage.Set(fmt.Sprintf("%s archives (%s)", humanize.Comma(c.prog.Current()), traversal.VirtualPath))
	}
}

func accessPath(loc file.Location) string {
	if loc.AccessPath != "" {
		return loc.AccessPath
	}
	return loc.RealPath
}

// runSubPipeline runs every cataloger task against the given resolver into a throwaway SBOM, so
// results can be attributed to the containing archive before merging into the shared SBOM.
//
// Failures are recorded as RunTask records them at the top level (executor.go), so they land in the
// SBOM's unknowns rather than only the logs: errors carrying coordinates keep them, anything left is
// attributed to archiveCoord. A failure here never fails the archive or the scan.
func (c *archiveCataloger) runSubPipeline(ctx context.Context, resolver file.Resolver, archiveCoord file.Coordinates) *sbom.SBOM {
	scratch := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:     pkg.NewCollection(),
			FileMetadata: map[file.Coordinates]file.Metadata{},
			FileDigests:  map[file.Coordinates][]file.Digest{},
			FileContents: map[file.Coordinates]string{},
			FileLicenses: map[file.Coordinates][]file.License{},
			Executables:  map[file.Coordinates]file.Executable{},
			Unknowns:     map[file.Coordinates][]string{},
		},
	}
	scratchBuilder := sbomsync.NewBuilder(scratch)
	for _, t := range c.subPipeline {
		err := runTaskSafely(ctx, t, resolver, scratchBuilder)
		if err == nil {
			continue
		}
		log.WithFields("task", t.Name(), "error", err).Trace("archive sub-cataloger task reported an error")

		unknowns, remaining := unknown.ExtractCoordinateErrors(err)
		if remaining != nil {
			unknowns = append(unknowns, unknown.CoordinateError{Coordinates: archiveCoord, Reason: remaining})
		}
		appendUnknowns(scratchBuilder, t.Name(), unknowns)
	}
	return scratch
}

// archiveCandidate is one file the walk will try to open, and how it came to be a candidate.
type archiveCandidate struct {
	location file.Location

	// sniffedAsArchive is true when the file's own content types it as an archive. Such a file that
	// cannot be extracted is a broken archive and is reported; a candidate here only because its head
	// might hide one is passed over silently.
	sniffedAsArchive bool
}

// zipArchiveGlobs find files worth a second look: those named like zip archives whose content did not
// sniff as one, such as a Spring Boot executable jar - a launcher stub with a zip appended, which
// sniffs as a shell script.
//
// Not a detection rule: the end-of-central-directory record settles whether a candidate is an
// archive, so a `.jar` holding prose is still refused. The name decides only what gets opened, which
// is why a self-extracting archive with no telling extension is not found.
//
// A glob rather than a MIME lookup because asking for every file sniffed as executable, script or
// unrecognized returns thousands of locations that are all discarded, which tripled the scan on a
// stock ruby image. One pattern per extension because brace alternation matched nothing.
var zipArchiveGlobs = []string{
	"**/*.jar", "**/*.war", "**/*.ear", "**/*.par", "**/*.sar", "**/*.nar", "**/*.kar",
	"**/*.hpi", "**/*.jpi", "**/*.far", "**/*.rar", "**/*.zip", "**/*.apk", "**/*.aar",
	"**/*.egg", "**/*.whl", "**/*.lpkg", "**/*.zap", "**/*.exe",
}

// discoverArchives returns every location worth opening: files that are archives by their own
// content, plus files named like zip archives whose head says script or executable but whose tail may
// still be a whole zip. The second group is only opened; the extractor refuses anything with no
// end-of-central-directory record.
//
// No exclusion filter here: exclusion patterns are applied where each filesystem is indexed, so an
// excluded archive is not in the resolver to begin with.
func (c *archiveCataloger) discoverArchives(resolver file.Resolver) []archiveCandidate {
	archives, err := resolver.FilesByMIMEType(mimetype.ArchiveMIMETypeSet.List()...)
	if err != nil {
		log.WithFields("error", err).Debug("unable to list archive files for recursive cataloging")
		return nil
	}

	candidates := make([]archiveCandidate, 0, len(archives))
	for _, loc := range archives {
		candidates = append(candidates, archiveCandidate{location: loc, sniffedAsArchive: true})
	}

	appended, err := resolver.FilesByGlob(zipArchiveGlobs...)
	if err != nil {
		// the archives found above are still worth walking
		log.WithFields("error", err).Debug("unable to list files that may carry an appended archive")
		return candidates
	}
	seen := make(map[file.Coordinates]struct{}, len(candidates))
	for _, c := range candidates {
		seen[c.location.Coordinates] = struct{}{}
	}
	for _, loc := range appended {
		// one file reached by both lookups must be opened once, or every package it holds is doubled
		if _, dup := seen[loc.Coordinates]; dup {
			continue
		}
		seen[loc.Coordinates] = struct{}{}
		candidates = append(candidates, archiveCandidate{location: loc})
	}
	return candidates
}

// mergeArchiveResults copies the throwaway SBOM's packages, files and relationships into the shared
// SBOM, adding a file-level CONTAINS relationship from the archive to everything found inside it.
func mergeArchiveResults(archiveCoord file.Coordinates, scratch *sbom.SBOM, builder sbomsync.Builder) {
	pkgs := scratch.Artifacts.Packages.Sorted()
	if len(pkgs) > 0 {
		builder.AddPackages(pkgs...)
	}

	accessor, _ := builder.(sbomsync.Accessor)
	if accessor != nil {
		accessor.WriteToSBOM(func(s *sbom.SBOM) {
			mergeFileArtifacts(s, scratch)
		})
	}

	var rels []artifact.Relationship
	for _, p := range pkgs {
		rels = append(rels, artifact.Relationship{
			From: archiveCoord,
			To:   p,
			Type: artifact.ContainsRelationship,
		})
	}
	for _, coord := range scratch.AllCoordinates() {
		rels = append(rels, artifact.Relationship{
			From: archiveCoord,
			To:   coord,
			Type: artifact.ContainsRelationship,
		})
	}
	// preserve relationships discovered within the archive (e.g. package evident-by file)
	rels = append(rels, scratch.Relationships...)

	if len(rels) > 0 {
		builder.AddRelationships(rels...)
	}
}

func mergeFileArtifacts(dst, src *sbom.SBOM) {
	if dst.Artifacts.FileMetadata == nil {
		dst.Artifacts.FileMetadata = map[file.Coordinates]file.Metadata{}
	}
	for k, v := range src.Artifacts.FileMetadata {
		dst.Artifacts.FileMetadata[k] = v
	}
	if dst.Artifacts.FileDigests == nil {
		dst.Artifacts.FileDigests = map[file.Coordinates][]file.Digest{}
	}
	for k, v := range src.Artifacts.FileDigests {
		dst.Artifacts.FileDigests[k] = v
	}
	if dst.Artifacts.FileContents == nil {
		dst.Artifacts.FileContents = map[file.Coordinates]string{}
	}
	for k, v := range src.Artifacts.FileContents {
		dst.Artifacts.FileContents[k] = v
	}
	if dst.Artifacts.FileLicenses == nil {
		dst.Artifacts.FileLicenses = map[file.Coordinates][]file.License{}
	}
	for k, v := range src.Artifacts.FileLicenses {
		dst.Artifacts.FileLicenses[k] = v
	}
	if dst.Artifacts.Executables == nil {
		dst.Artifacts.Executables = map[file.Coordinates]file.Executable{}
	}
	for k, v := range src.Artifacts.Executables {
		dst.Artifacts.Executables[k] = v
	}
	if dst.Artifacts.Unknowns == nil {
		dst.Artifacts.Unknowns = map[file.Coordinates][]string{}
	}
	for k, v := range src.Artifacts.Unknowns {
		dst.Artifacts.Unknowns[k] = append(dst.Artifacts.Unknowns[k], v...)
	}
}

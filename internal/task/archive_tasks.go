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
// archives, whose cataloger skips its own unarchiving when this task is enabled), treats each as
// its own standalone indexed filesystem, runs the given cataloger sub-pipeline against each, and
// records file-level CONTAINS relationships from the archive to the packages and files discovered
// inside it. Returns nil when archive cataloging is disabled (MaxDepth <= 0), so a disabled feature
// registers no task at all rather than a task that runs and does nothing.
//
// subPipeline is the set of package/file cataloger tasks to run against each extracted archive; it
// must NOT include this task, so recursion is driven only by the explicit depth-limited walk here.
// newResolver builds an FSID-stamped indexed resolver over an extracted archive directory (injected
// so this package does not depend on the syft-subtree internal fileresolver package).
func NewArchiveCatalogerTask(cfg cataloging.ArchiveSearchConfig, subPipeline []Task, newResolver archive.ResolverFactory, newStoreResolver archive.StoreResolverFactory, notify archive.Notify) Task {
	if cfg.MaxDepth == 0 || newResolver == nil {
		return nil
	}

	// this task drives recursion itself via an explicit depth-bounded walk, so it must never appear
	// in its own sub-pipeline: each nesting level would then be processed once by the walk and
	// again by the nested copy. Enforced rather than left to a comment, since the caller assembles
	// the sub-pipeline from whatever package and file tasks are selected.
	subPipeline = withoutArchiveCataloger(subPipeline)
	if len(subPipeline) == 0 {
		return nil
	}
	fn := func(ctx context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		// one progress row for the whole recursive walk, updated as each archive is entered. The
		// sub-pipeline underneath it reports into this same row rather than starting rows of its own:
		// those catalogers have already started (and finished) a row for the scan root, and starting
		// them again per archive is what both floods the display and strands the rows it replaces
		// (see bus.WithCatalogerTaskProgress).
		prog := bus.StartCatalogerTask(ctx, archiveCatalogerProgressInfo(), -1, "")
		c := &archiveCataloger{
			cfg:              cfg,
			subPipeline:      subPipeline,
			extractors:       archive.DefaultExtractors(),
			limits:           archive.DefaultExtractionLimits(cfg),
			limiter:          archive.NewLimiter(archive.DefaultLimits(cfg)),
			newResolver:      newResolver,
			newStoreResolver: newStoreResolver,
			notify:           notify,
			prog:             prog,
		}
		err := c.catalog(archive.WithLimiter(bus.WithCatalogerTaskProgress(ctx, prog), c.limiter), resolver, nil, 0, builder)
		c.left()
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

// withoutArchiveCataloger returns the given tasks with any archive-cataloger task removed.
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
	limits           archive.ExtractionLimits
	newResolver      archive.ResolverFactory
	newStoreResolver archive.StoreResolverFactory

	// notify carries structured extraction events - which archive overflowed to disk and why, which was
	// skipped - to whoever asked for them. Nil is the no-op, and nil is what a scan that wants nothing
	// instrumented passes.
	notify archive.Notify

	// limiter measures the archive content this scan is holding right now, falling as each archive is
	// released. One instance per task run, because one task run is one scan and that is the only
	// scoping under which "held at once" means anything. It replaces a monotonic byte counter, which
	// bounded a number matching no state that ever existed: every archive's extraction directory is
	// removed on the way out while the counter only ever rose.
	limiter *archive.Limiter

	// prog is the single progress row for the whole walk: its stage names the archive currently being
	// cataloged and its count is the number of archives entered so far. The recursion reports through
	// this one row rather than letting the sub-pipeline start rows of its own at every level.
	prog *monitor.TaskProgress

	// slowest is the archive that spent the most time on its own extraction and cataloging, named by
	// its full virtual path. Guarded for the same reason the limiter is: the walk is sequential today
	// and lives in a concurrent neighbourhood.
	statsMu      sync.Mutex
	slowest      time.Duration
	slowestPath  string
	archivesSeen int64
}

// recordArchiveTime keeps the longest self time seen and the archive that spent it. Self time
// excludes the archives nested inside this one, which are timed against themselves - inclusive time
// would name the outermost archive every run and say nothing.
func (c *archiveCataloger) recordArchiveTime(virtualPath string, took time.Duration) {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	c.archivesSeen++
	if took > c.slowest {
		c.slowest = took
		c.slowestPath = virtualPath
	}
}

// logStats reports what the walk cost, once, when it is done. The two peaks are the high-water marks
// of the gauges the limits are enforced against, so they are directly comparable to the configured
// bounds - they are not process memory and not filesystem usage. Reported at info rather than debug
// because it is one line per scan and it is what someone tuning the limits is looking for; the
// per-archive skip and truncation lines around it stay at debug.
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
// parent is the traversal for the archive whose contents are being searched (nil at the scan root).
func (c *archiveCataloger) catalog(ctx context.Context, resolver file.Resolver, parent *archive.Traversal, depth int, builder sbomsync.Builder) error {
	if c.cfg.MaxDepth >= 0 && depth >= c.cfg.MaxDepth {
		return nil
	}

	var errs error
	for _, candidate := range c.discoverArchives(resolver) {
		// there is no between-archives check: a limit falls when an archive is released, so an
		// archive that does not fit says nothing about the next one, and reaching a bound skips only
		// the archive that reached it.
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

	// a candidate that is only a candidate is checked cheaply before its bytes are read in full: an
	// archive wearing a stub carries an entry signature near the front, and almost nothing else does.
	// Reading every executable in a scan to its end to ask the authoritative question instead doubled
	// a stock ruby image.
	var archiveContent io.Reader = content
	if !candidate.sniffedAsArchive {
		var mayHide bool
		archiveContent, mayHide = archive.MayHideAnAppendedArchive(content)
		if !mayHide {
			return nil
		}
	}

	// self time for this archive: its extraction, its sub-pipeline and its merge, stopped before the
	// recursive descent so a containing archive is not charged for what it contains
	started := time.Now()

	// the extracted files inherit the filesystem id of the location the archive was found at,
	// uniformly at every level: for an image source that is the layer digest, for a directory source
	// it is empty, and inside another archive the enclosing resolver stamped it there already. The
	// nesting chain is carried separately as the archive path (the colon-delimited chain of archive
	// access paths from the scan root). Together these keep identically-named files in different
	// archives - and the same archive path in different layers - apart in the coordinate-keyed tables.
	archivePath := parent.VirtualPathOf(accessPath(archiveLoc))
	extracted, err := archive.ExtractToResolver(ctx, archiveContent, archiveLoc.AccessPath, archiveLoc.FileSystemID, archivePath, c.extractors, c.limiter, c.limits, c.newResolver, c.newStoreResolver, c.notify)
	if errors.Is(err, archive.ErrDiskLimitReached) {
		// the disk limit is terminal and nothing will be released while this archive waits, since
		// the walk descends before it unwinds - so the archive is skipped and the scan continues.
		// Attributed to the archive, because a log line carrying only the bound says nothing about
		// what was lost.
		log.WithFields("archive", accessPath(archiveLoc), "limit", c.cfg.MaxDiskBytes).
			Debug("skipping archive whose content would exceed the disk limit")
		return nil
	}
	if err != nil {
		return err
	}
	if extracted == nil {
		// nothing could open it: a format with no extractor (an ar archive, a bare gzip that is not a
		// tar), or a candidate whose head could have been hiding an archive and was not. Logged, not
		// returned as an error.
		//
		// Returning one was measured at 3x the scan on a stock ruby image, whose 3,679 gzip files are
		// mostly man pages with no extractor: every one produced an error, and appending thousands of
		// them into one chain that is then walked for coordinate errors is quadratic. A file syft
		// cannot open is also not the failure `#archive-failure-is-not-fatal` is about - that is a
		// corrupt archive, which fails during extraction and still returns an error from there.
		log.WithFields("archive", accessPath(archiveLoc), "sniffed-as-archive", candidate.sniffedAsArchive).
			Trace("no extractor could read this candidate; skipping")
		return nil
	}
	// releases the extraction directory and gives back everything this archive charged to the
	// limiter, after the sub-pipeline and after recursion
	defer extracted.Cleanup()

	if extracted.Result.Truncated() {
		// a bound stopped the extraction early: catalog what was written rather than discarding the
		// archive, but say so, since the packages found here are not the full set. Recorded in the
		// SBOM's unknowns and not only in the logs, because "syft saw part of this archive" is a fact
		// about the SBOM's completeness that outlives the run that produced it - which is exactly what
		// unknowns are for.
		log.WithFields("archive", accessPath(archiveLoc), "limit", string(extracted.Result.Truncation)).
			Debug("archive extraction truncated by a configured limit; cataloging partial contents")

		appendUnknowns(builder, ArchiveCatalogerTaskName, []unknown.CoordinateError{{
			Coordinates: archiveLoc.Coordinates,
			Reason: fmt.Errorf("archive cataloged from part of its contents: extraction stopped at the %s",
				string(extracted.Result.Truncation)),
		}})
	}

	// expose the nesting chain to catalogers in the sub-pipeline (and deeper recursion) so they can
	// reconstruct nesting-aware identity (e.g. the java cataloger's colon-delimited virtual paths)
	trav := &archive.Traversal{
		Location:     archiveLoc,
		VirtualPath:  archivePath,
		FileSystemID: extracted.FileSystemID,
		Depth:        depth + 1,
		Parent:       parent,
		Digests:      extracted.Digests,
	}
	subCtx := archive.WithTraversal(ctx, trav)

	c.entering(trav.VirtualPath)

	// run the package/file cataloger sub-pipeline against the archive's standalone filesystem
	scratch := c.runSubPipeline(subCtx, extracted.Resolver, archiveLoc.Coordinates)

	// merge results into the shared SBOM and record file-level CONTAINS edges from this archive
	mergeArchiveResults(archiveLoc.Coordinates, scratch, builder)

	c.left()
	c.recordArchiveTime(trav.VirtualPath, time.Since(started))

	// recurse into archives nested within this one
	return c.catalog(subCtx, extracted.Resolver, trav, depth+1, builder)
}

// entering records on the walk's single progress row that this archive is now being cataloged, and
// left takes that row's stage back once it is done. Both are nil-safe, so a cataloger assembled
// without a progress row simply reports nothing.
//
// The row is taken back because the sub-pipeline shares its stage - that is what makes the nested
// catalogers' progress visible - and each of them signs off with a summary of its own ("0
// executables"). Left to stand, that summary is what the row reads while the next archive is being
// extracted, which is both wrong and unchanging. The count of archives entered is the one thing the
// row can say that is always true of the walk as a whole.
func (c *archiveCataloger) entering(virtualPath string) {
	if c.prog == nil {
		return
	}
	c.prog.Increment()
	c.prog.AtomicStage.Set(virtualPath)
}

func (c *archiveCataloger) left() {
	if c.prog == nil {
		return
	}
	c.prog.AtomicStage.Set(fmt.Sprintf("%s archives", humanize.Comma(c.prog.Current())))
}

// accessPath returns the location's access path, falling back to the real path when unset.
func accessPath(loc file.Location) string {
	if loc.AccessPath != "" {
		return loc.AccessPath
	}
	return loc.RealPath
}

// runSubPipeline runs every cataloger task against the given resolver into a throwaway SBOM so the
// results can be attributed to the containing archive before being merged into the shared SBOM.
//
// A task's failure is recorded the same way RunTask records one at the top level (executor.go), so a
// cataloger that fails inside an archive is visible in the SBOM's unknowns rather than only in the
// logs: errors carrying their own coordinates keep them, and anything left has no location of its
// own, so it is attributed to archiveCoord - the archive that was being cataloged. A failure here
// never fails the archive or the scan.
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
	// then cannot be extracted is a broken archive and is reported; a candidate that got here only
	// because its head could be hiding one is simply not an archive, and is passed over in silence.
	sniffedAsArchive bool
}

// zipArchiveGlobs find the files worth a second look: those that claim to be zip archives by name
// and whose content did not say so. A self-extracting archive is one - a launcher stub with a zip
// concatenated onto it, typed by the stub - and the canonical case is a Spring Boot executable jar,
// which sniffs as a shell script.
//
// This is not a detection rule. Whether a candidate is an archive is settled by the
// end-of-central-directory record and by nothing else, so a file named `.jar` that holds prose is
// refused exactly as it is today. The name decides only what gets looked at.
//
// It is a glob rather than a MIME lookup because the MIME lookup was the whole cost. Asking the
// resolver for every file that sniffs as executable, script, or unrecognized returns 3,274 locations
// on a stock ruby image - all of which this then discarded, since none of them were named like
// archives - and that one call took the scan from 15 seconds to 45. Asking for the names directly
// returns the handful that matter.
//
// The limit this accepts is that a self-extracting archive with no telling extension is not found.
// That is deliberate, and it is the one place here where a name decides whether syft looks.
//
// One pattern per extension, not one pattern with brace alternation: the alternation form matched
// nothing, and the cost of the extra patterns is not measurable - the whole lookup is about a
// millisecond and returns nothing on an image with no self-extracting archives in it.
var zipArchiveGlobs = []string{
	"**/*.jar", "**/*.war", "**/*.ear", "**/*.par", "**/*.sar", "**/*.nar", "**/*.kar",
	"**/*.hpi", "**/*.jpi", "**/*.far", "**/*.rar", "**/*.zip", "**/*.apk", "**/*.aar",
	"**/*.egg", "**/*.whl", "**/*.lpkg", "**/*.zap", "**/*.exe",
}

// discoverArchives returns every location worth opening, in two groups.
//
// There is no exclusion filter here on purpose. The scan's exclusion patterns are applied where each
// filesystem is indexed - the source's own index for the scan root, and the extraction directory's
// index for an archive's contents - so an excluded archive is not in the resolver to be returned in
// the first place. Filtering again here would be a second mechanism answering the same question.
//
// The archive MIME types are archives by their own content. The appended set are files whose head
// says script or executable and whose tail may still be a whole zip: a self-extracting archive is
// typed by its stub, so nothing sniffed at offset zero can see it. Membership in the second set
// decides only that a file is worth opening - whether it is an archive is decided by the extractor,
// which refuses anything with no end-of-central-directory record.
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
		// a location reached by both lookups is one file and must be opened once. The two sets are
		// disjoint today, so this guards the invariant rather than a known overlap - and processing
		// an archive twice would double every package it holds, which is the failure this whole
		// design exists to prevent.
		if _, dup := seen[loc.Coordinates]; dup {
			continue
		}
		seen[loc.Coordinates] = struct{}{}
		candidates = append(candidates, archiveCandidate{location: loc})
	}
	return candidates
}

// mergeArchiveResults copies the throwaway SBOM's packages, files, and relationships into the shared
// SBOM, and adds a file-level CONTAINS relationship from the archive's coordinates to every package
// and file discovered inside it.
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

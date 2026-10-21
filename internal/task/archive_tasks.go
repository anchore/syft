package task

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"runtime/debug"
	"slices"
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

// NewArchiveCatalogerTask returns a task that extracts every archive it finds, runs the same tasks
// against the archive's contents as a standalone filesystem, and records
// CONTAINS relationships from the archive to what was found inside it. It recurses into the archives
// it extracts up to cfg.MaxDepth; the task drops itself from the tasks so that is the only recursion.
//
// Each archive is handled as the scan root is: pkgTasks, then the archives nested in it, then fileTasks,
// which see the packages found in the nested archives (see Traversal.PackageFiles).
//
// The task is the authority on which archives were not cataloged and why; with
// unknowns.IncludeUnexpandedArchives it also reports archives in formats it does not extract.
//
// exclusions are the scan's exclusion patterns, applied inside each archive. Returns nil when archive
// cataloging is disabled (MaxDepth == 0; negative means as deep as unboundedArchiveDepth).
func NewArchiveCatalogerTask(cfg cataloging.ArchiveSearchConfig, unknowns cataloging.UnknownsConfig, pkgTasks, fileTasks []Task, exclusions []string) Task {
	return newArchiveCatalogerTask(cfg.MaxDepth, archiveLimits(cfg), unknowns.IncludeUnexpandedArchives, pkgTasks, fileTasks, exclusions)
}

func archiveLimits(cfg cataloging.ArchiveSearchConfig) archive.Limits {
	return archive.Limits{MaxMemoryBytes: cfg.MaxMemoryBytes, MaxDiskBytes: cfg.MaxDiskBytes}
}

func newArchiveCatalogerTask(maxDepth int, limits archive.Limits, reportUnsupportedUnknowns bool, pkgTasks, fileTasks []Task, exclusions []string) Task {
	if maxDepth == 0 {
		return nil
	}
	pkgTasks, fileTasks = withoutArchiveCataloger(pkgTasks), withoutArchiveCataloger(fileTasks)
	if len(pkgTasks)+len(fileTasks) == 0 {
		return nil
	}

	fn := func(ctx context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		// catalogers run once per archive, and each must report into the one progress row it owns
		ctx = bus.WithCatalogerTaskRegistry(ctx)

		c := &archiveCataloger{
			maxDepth:                  maxDepth,
			reportUnsupportedUnknowns: reportUnsupportedUnknowns,
			pkgTasks:                  pkgTasks,
			fileTasks:                 fileTasks,
			limiter:                   archive.NewLimiter(limits),
			exclusions:                archive.NewExclusions(exclusions),
			progress:                  bus.StartCatalogerTask(ctx, archiveCatalogerProgressInfo(), -1, ""),
		}
		err := c.catalog(ctx, resolver, 0, builder)
		c.progress.AtomicStage.Set(fmt.Sprintf("%s archives", humanize.Comma(c.progress.Current())))
		c.progress.SetCompleted()
		c.logStats()
		return err
	}
	return NewTask(ArchiveCatalogerTaskName, fn, pkgcataloging.PackageTag, "archive")
}

func archiveCatalogerProgressInfo() monitor.GenericTask {
	return monitor.GenericTask{
		Title: monitor.Title{
			Default: "Archives",
		},
		ID:       ArchiveCatalogerTaskName,
		ParentID: monitor.TopLevelCatalogingTaskID,
	}
}

func withoutArchiveCataloger(tasks []Task) []Task {
	var out []Task
	for _, t := range tasks {
		if t == nil || t.Name() == ArchiveCatalogerTaskName {
			continue
		}
		out = append(out, t)
	}
	return out
}

type archiveCataloger struct {
	maxDepth                  int
	reportUnsupportedUnknowns bool
	pkgTasks                  []Task
	fileTasks                 []Task
	limiter                   *archive.Limiter
	exclusions                archive.Exclusions

	// progress is the one row for the whole walk: its count is how many archives have been entered
	progress *monitor.TaskProgress

	// ancestors are the digests of the archives the walk is currently inside. The walk is depth-first
	// and sequential, so this is a stack.
	ancestors []file.Digest

	// the archive that spent the longest on its own extraction and cataloging, excluding nested archives
	slowest     time.Duration
	slowestPath string
}

// logStats reports what the walk cost, once. The peaks are the most held against each limit at any
// one moment, comparable to the configured bounds.
func (c *archiveCataloger) logStats() {
	peakMemory, peakDisk := c.limiter.Peak()
	fields := []any{
		"archives", c.progress.Current(),
		"peak-memory", humanize.Bytes(uint64(peakMemory)),
		"peak-disk", humanize.Bytes(uint64(peakDisk)),
	}
	if c.slowestPath != "" {
		fields = append(fields, "slowest", c.slowestPath, "slowest-took", c.slowest.Round(time.Millisecond))
	}
	log.WithFields(fields...).Info("nested archive cataloging complete")
}

// unboundedArchiveDepth is the depth a negative MaxDepth stops at. No real nesting comes close, and a
// hostile archive (a zip quine, a recursive bomb) must still end.
const unboundedArchiveDepth = 16

// catalog processes every archive in the resolver, recursing into each up to maxDepth.
func (c *archiveCataloger) catalog(ctx context.Context, resolver file.Resolver, depth int, builder sbomsync.Builder) error {
	return c.catalogCandidates(ctx, resolver, c.discoverArchives(resolver), depth, builder)
}

func (c *archiveCataloger) catalogCandidates(ctx context.Context, resolver file.Resolver, candidates []archiveCandidate, depth int, builder sbomsync.Builder) error {
	maxDepth := c.maxDepth
	if maxDepth < 0 {
		maxDepth = unboundedArchiveDepth
	}
	if depth >= maxDepth {
		// java's own recursion is off while this task runs, so an archive left here is otherwise lost
		// without a trace
		for _, candidate := range candidates {
			if candidate.sniffedAsArchive {
				recordArchiveUnknown(builder, candidate.location.Coordinates, "nested archive not cataloged: the nested archive depth limit was reached")
			}
		}
		return nil
	}
	var errs error
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.processArchive(ctx, resolver, candidate, depth, builder); err != nil {
			errs = unknown.Append(errs, candidate.location, err)
		}
	}
	return errs
}

// processArchive processes the given candidate archive, catching panics
//
//nolint:funlen
func (c *archiveCataloger) processArchive(ctx context.Context, parentResolver file.Resolver, candidate archiveCandidate, depth int, builder sbomsync.Builder) (err error) {
	// the decoders run on untrusted bytes; a panic in one costs this archive, not the scan
	defer func() {
		if r := recover(); r != nil {
			// the stack goes to the log, not the reason: the reason lands in the published SBOM's unknowns
			log.WithFields("path", candidate.location.FullNestedPath()).Debugf("archive cataloging panic stack:\n%s", debug.Stack())
			err = fmt.Errorf("panic while cataloging archive: %v", r)
		}
	}()

	location := candidate.location
	content, err := parentResolver.FileContentsByLocation(location)
	if err != nil {
		return err
	}
	defer internal.CloseAndLogError(content, location.AccessPath)

	var archiveContent io.Reader = content
	if !candidate.sniffedAsArchive {
		var mayHide bool
		if archiveContent, mayHide = archive.MayHideAnAppendedArchive(content); !mayHide {
			return nil
		}
	}

	started := time.Now()

	if depth == 0 {
		// one budget for this archive and everything nested in it, however deep
		ctx = archive.WithBudget(ctx, archive.NewBudget(archiveTreeBudget(parentResolver, location)))
	}

	// extracted files keep the real path and filesystem ID of the outermost archive; the chain of entries
	// to each is carried as its archive path. The chain names real paths, not the link the archive was
	// reached by, so it is stable and joins to the archive's package location by prefix.
	traversal := &archive.Traversal{Location: location, Parent: archive.TraversalFromContext(ctx)}
	archivePath := location.FullNestedPath()
	extracted, err := archive.Extract(ctx, archiveContent, location.Coordinates, c.limiter, c.exclusions)
	if errors.Is(err, archive.ErrUnsupportedFormat) {
		if c.reportUnsupportedUnknowns {
			recordArchiveUnknown(builder, location.Coordinates, "archive not cataloged: "+err.Error())
		}
		return nil
	}
	if errors.Is(err, archive.ErrDiskLimitReached) {
		// nothing is released while this archive waits, so skip it rather than block the scan
		recordArchiveUnknown(builder, location.Coordinates, "archive skipped: its content would exceed the disk limit")
		return nil
	}
	if err != nil {
		return err
	}
	if extracted == nil {
		// a format with no extractor, or a candidate whose head only looked like an appended archive.
		// Logged rather than returned: an image can hold thousands of these
		log.WithFields("archive", archivePath, "sniffed-as-archive", candidate.sniffedAsArchive).
			Trace("no extractor could read this candidate; skipping")
		return nil
	}
	defer extracted.Cleanup()

	// an archive whose bytes match one it is nested in (a zip quine) would recurse forever
	if c.isAncestor(extracted.Digests) {
		recordArchiveUnknown(builder, location.Coordinates, "archive not cataloged: it is identical to an archive that contains it")
		return nil
	}
	c.ancestors = append(c.ancestors, extracted.Digests...)
	defer func() { c.ancestors = c.ancestors[:len(c.ancestors)-len(extracted.Digests)] }()

	if extracted.Truncated != nil {
		recordArchiveUnknown(builder, location.Coordinates, "archive cataloged from part of its contents: "+extracted.Truncated.Error())
	}

	traversal.Digests = extracted.Digests
	ctx = archive.WithTraversal(ctx, traversal)

	c.progress.Increment()

	// everything found in this archive and the archives nested in it, merged into the parent's SBOM once complete
	found := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	foundBuilder := sbomsync.NewBuilder(found)
	runArchiveTasks(ctx, c.pkgTasks, extracted, location.Coordinates, foundBuilder)
	direct := found.Artifacts.Packages.Sorted()
	traversal.Packages = packagesAt(direct, location.Coordinates)

	// self time excludes descending, so a containing archive is not charged for what it contains
	selfTime := time.Since(started)

	// as at the scan root, nested archives are cataloged before this archive's files, so the packages
	// describing them (located in this archive) select their files here
	children := c.discoverArchives(extracted)
	errs := c.catalogCandidates(ctx, extracted, children, depth+1, foundBuilder)

	started = time.Now()
	runArchiveTasks(ctx, c.fileTasks, extracted, location.Coordinates, foundBuilder)
	addContains(location.Coordinates, archivePath, direct, children, found)
	mergeArchiveResults(found, builder)
	c.progress.AtomicStage.Set(humanize.Comma(c.progress.Current()) + " archives (" + archivePath + ")")

	if took := selfTime + time.Since(started); took > c.slowest {
		c.slowest, c.slowestPath = took, archivePath
	}

	return errs
}

// a top-level archive and everything nested in it may decompress to archiveTreeRatio times its size, or
// archiveTreeFloorBytes if that is more. Real trees (a war of jars, a layer of tarballs) expand a few
// times over; a recursive bomb expands by orders of magnitude at every level.
var (
	archiveTreeRatio      int64 = 100
	archiveTreeFloorBytes int64 = 1 << 30
)

func archiveTreeBudget(resolver file.Resolver, location file.Location) int64 {
	var size int64
	if m, err := resolver.FileMetadataByLocation(location); err == nil && m.FileInfo != nil {
		size = m.Size()
	}
	return max(archiveTreeRatio*size, archiveTreeFloorBytes)
}

func (c *archiveCataloger) isAncestor(digests []file.Digest) bool {
	for _, d := range digests {
		if slices.Contains(c.ancestors, d) {
			return true
		}
	}
	return false
}

// packagesAt returns the packages located at the given coordinates, i.e. those describing the file there.
func packagesAt(pkgs []pkg.Package, coordinates file.Coordinates) []pkg.Package {
	var out []pkg.Package
	for _, p := range pkgs {
		if locatedAt(p, coordinates) {
			out = append(out, p)
		}
	}
	return out
}

// locatedAt reports whether one of p's locations is at the given coordinates.
func locatedAt(p pkg.Package, coordinates file.Coordinates) bool {
	for _, l := range p.Locations.ToUnorderedSlice() {
		if l.Coordinates == coordinates {
			return true
		}
	}
	return false
}

func recordArchiveUnknown(builder sbomsync.Builder, coordinates file.Coordinates, reason string) {
	appendUnknowns(builder, ArchiveCatalogerTaskName, []unknown.CoordinateError{{Coordinates: coordinates, Reason: errors.New(reason)}})
}

// runArchiveTasks runs each task against the archive's contents.
//
// Failures are recorded as RunTask records them at the top level: errors carrying coordinates keep
// them, anything else is attributed to the archive. A failure never fails the archive or the scan.
func runArchiveTasks(ctx context.Context, tasks []Task, resolver file.Resolver, archiveCoordinates file.Coordinates, builder sbomsync.Builder) {
	for _, t := range tasks {
		err := runSubTaskSafely(ctx, t, resolver, builder)
		if err == nil {
			continue
		}
		log.WithFields("task", t.Name(), "error", err).Trace("archive sub-cataloger task reported an error")

		unknowns, remaining := unknown.ExtractCoordinateErrors(err)
		if remaining != nil {
			unknowns = append(unknowns, unknown.CoordinateError{Coordinates: archiveCoordinates, Reason: remaining})
		}
		appendUnknowns(builder, t.Name(), unknowns)
	}
}

// runSubTaskSafely is runTaskSafely without the task name in a panic's error, since appendUnknowns
// already prefixes it.
func runSubTaskSafely(ctx context.Context, t Task, resolver file.Resolver, builder sbomsync.Builder) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.WithFields("task", t.Name()).Debugf("archive sub-cataloger task panic stack:\n%s", debug.Stack())
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return t.Execute(ctx, resolver, builder)
}

// archiveCandidate is one file the walk will try to open.
type archiveCandidate struct {
	location file.Location

	// sniffedAsArchive is true when the file's content types it as an archive. Such a file that cannot
	// be extracted is a broken archive and is reported; a file that is a candidate only by name is
	// passed over silently.
	sniffedAsArchive bool
}

// zipArchiveGlobs find files named like zip archives whose content did not sniff as one, such as a
// Spring Boot executable jar: a launcher script with a zip appended. The name only decides what gets
// opened; the end-of-central-directory record decides whether it is an archive.
//
// Globs rather than a MIME lookup, because asking for every executable, script and unrecognized file
// returned thousands of locations that were all discarded.
var zipArchiveGlobs = []string{
	"**/*.jar", "**/*.war", "**/*.ear", "**/*.par", "**/*.sar", "**/*.nar", "**/*.kar",
	"**/*.hpi", "**/*.jpi", "**/*.far", "**/*.rar", "**/*.zip", "**/*.apk", "**/*.aar",
	"**/*.egg", "**/*.whl", "**/*.lpkg", "**/*.zap", "**/*.exe",
}

var archiveMIMETypes = slices.Sorted(slices.Values(mimetype.ArchiveMIMETypeSet.List()))

// discoverArchives returns every file worth opening: those whose content is an archive, plus those
// named like a zip whose tail may still hold one.
func (c *archiveCataloger) discoverArchives(resolver file.Resolver) []archiveCandidate {
	archives, err := resolver.FilesByMIMEType(archiveMIMETypes...)
	if err != nil {
		log.WithFields("error", err).Debug("unable to list archive files for recursive cataloging")
		return nil
	}

	var candidates []archiveCandidate
	seen := map[file.Coordinates]int{}
	for _, loc := range archives {
		seen[loc.Coordinates] = len(candidates)
		candidates = append(candidates, archiveCandidate{location: loc, sniffedAsArchive: true})
	}

	namedLikeZips, err := resolver.FilesByGlob(zipArchiveGlobs...)
	if err != nil {
		log.WithFields("error", err).Debug("unable to list files that may carry an appended archive")
		return candidates
	}
	for _, loc := range namedLikeZips {
		if i, dup := seen[loc.Coordinates]; dup {
			// a MIME hit is the bare real path; the name it is reached by (a link such as
			// lib/dep.jar -> ../store/3f9a1c) is what name-based catalogers like java key off
			if prev := candidates[i].location; prev.AccessPath == "" || prev.AccessPath == prev.FullNestedPath() {
				candidates[i].location = loc
			}
			continue
		}
		seen[loc.Coordinates] = len(candidates)
		candidates = append(candidates, archiveCandidate{location: loc})
	}
	return candidates
}

// mergeArchiveResults copies everything found in an archive into its parent's SBOM.
func mergeArchiveResults(found *sbom.SBOM, builder sbomsync.Builder) {
	if pkgs := found.Artifacts.Packages.Sorted(); len(pkgs) > 0 {
		builder.AddPackages(pkgs...)
	}
	if accessor, ok := builder.(sbomsync.Accessor); ok {
		accessor.WriteToSBOM(func(s *sbom.SBOM) {
			mergeFileArtifacts(&s.Artifacts, &found.Artifacts)
		})
	}
	if len(found.Relationships) > 0 {
		builder.AddRelationships(found.Relationships...)
	}
}

// addContains adds a CONTAINS relationship from the archive to each package found directly in it, each
// file directly in it that the SBOM describes, and each nested archive, so the hierarchy is navigable
// whatever file selection is configured.
//
// Files directly in the archive are those whose container is the archive's own full path, which leaves
// out the archive itself (a java package or an unknown recorded at its coordinates would otherwise
// become a self-loop) and the files of nested archives, contained by those.
func addContains(archiveCoordinates file.Coordinates, archivePath string, direct []pkg.Package, children []archiveCandidate, found *sbom.SBOM) {
	contained := file.NewCoordinateSet()
	for _, child := range children {
		contained.Add(child.location.Coordinates)
	}
	addInside := func(coordinates file.Coordinates) {
		if archive.ContainerPath(coordinates) == archivePath {
			contained.Add(coordinates)
		}
	}
	eachFileArtifactCoordinates(&found.Artifacts, addInside)
	for _, r := range found.Relationships {
		if c, ok := r.From.(file.Coordinates); ok {
			addInside(c)
		}
		if c, ok := r.To.(file.Coordinates); ok {
			addInside(c)
		}
	}

	var rels []artifact.Relationship
	for _, p := range direct {
		rels = append(rels, artifact.Relationship{From: archiveCoordinates, To: p, Type: artifact.ContainsRelationship})
	}
	for _, coordinates := range contained.ToSlice() {
		rels = append(rels, artifact.Relationship{From: archiveCoordinates, To: coordinates, Type: artifact.ContainsRelationship})
	}
	found.Relationships = append(found.Relationships, rels...)
}

// eachFileArtifactCoordinates calls fn with the coordinates of every file artifact, once per artifact
// kind describing it.
func eachFileArtifactCoordinates(a *sbom.Artifacts, fn func(file.Coordinates)) {
	for c := range a.FileMetadata {
		fn(c)
	}
	for c := range a.FileDigests {
		fn(c)
	}
	for c := range a.FileContents {
		fn(c)
	}
	for c := range a.FileLicenses {
		fn(c)
	}
	for c := range a.Executables {
		fn(c)
	}
	for c := range a.Unknowns {
		fn(c)
	}
}

func mergeFileArtifacts(dst, src *sbom.Artifacts) {
	mergeInto(&dst.FileMetadata, src.FileMetadata)
	mergeInto(&dst.FileDigests, src.FileDigests)
	mergeInto(&dst.FileContents, src.FileContents)
	mergeInto(&dst.FileLicenses, src.FileLicenses)
	mergeInto(&dst.Executables, src.Executables)
	if len(src.Unknowns) > 0 && dst.Unknowns == nil {
		dst.Unknowns = map[file.Coordinates][]string{}
	}
	for coordinates, reasons := range src.Unknowns {
		dst.Unknowns[coordinates] = append(dst.Unknowns[coordinates], reasons...)
	}
}

func mergeInto[K comparable, V any](dst *map[K]V, src map[K]V) {
	if len(src) == 0 {
		return
	}
	if *dst == nil {
		*dst = make(map[K]V, len(src))
	}
	maps.Copy(*dst, src)
}

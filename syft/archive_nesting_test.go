package syft

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/discard"
	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source/directorysource"
)

// This file covers nesting across archive families. The other nested-archive fixtures are all zips,
// so a zip-specific mechanism would pass them; the requirement here is that an archive of one family
// inside another behaves as it would inside its own family - same packages, same filesystem-id chain,
// same CONTAINS edges, same depth accounting.
//
// Chains are built in the test rather than committed as binaries, so each case can vary which family
// sits at which level.

// archiveFamily is one archive format buildNestedArchive can produce.
//
// ".jar" is its own family rather than a flavour of zip: the java cataloger meets it as a jar wherever
// it sits, while the archive task descends into it like any other zip. That differs mid-chain from at
// the leaf, so the matrix below uses a jar as container and as payload.
type archiveFamily string

const (
	familyZip   archiveFamily = ".zip"
	familyJar   archiveFamily = ".jar"
	familyTar   archiveFamily = ".tar"
	familyTarGz archiveFamily = ".tar.gz"
	familyTgz   archiveFamily = ".tgz"
)

// nestPlan describes one chain to build: a family per level (outermost first), the entries for the
// innermost archive, and extras to add beside the nested archive at a given level. The extras grade
// the levels' sizes or entry counts, which is how the limit cases place a bound between two levels.
type nestPlan struct {
	families []archiveFamily
	leaf     map[string][]byte
	extra    map[int]map[string][]byte
}

// nestedArchive is one built chain: the outermost archive's bytes, and the addresses that chain
// composes to at each level.
type nestedArchive struct {
	// name is the outermost archive's file name, as written into the scanned directory.
	name string
	// bytes is the outermost archive.
	bytes []byte
	// sizes is each archive's size in bytes, outermost first. A container is never smaller than what it
	// holds, so these decrease, and the limit cases place a bound between two of them.
	sizes []int
	// paths is each archive's path within its parent, outermost first; paths[0] is name.
	paths []string
	// fileSystemIDs is the composed chain each archive's own contents carry, outermost first.
	fileSystemIDs []string
	// virtualPaths is the same chain in java's colon-joined form, outermost first.
	virtualPaths []string
}

// nestingRow is one line of the depth-3 matrix.
type nestingRow struct {
	name     string
	families []archiveFamily
	why      string
}

// nestingVisit is one filesystem the archive cataloger's sub-pipeline was run against.
type nestingVisit struct {
	virtualPath string
	depth       int
	// overflowed names the archives whose content was on disk at this moment, sampled only when the
	// probe was given a temp dir to look in.
	overflowed []string
	// diskBytes is the scan's draw on the disk budget at this moment, read from the limiter on the
	// context (Limiter.InUse): spilled archive content, entry blobs, and index records charged to disk.
	// It exceeds the bytes in the work directories, since index records are charged too.
	diskBytes int64
}

// nestingProbe is a stub cataloger recording one visit per filesystem the archive cataloger runs its
// sub-pipeline against, reading the chain off the traversal on the context. It lets a case assert
// which archives were cataloged rather than inferring it from the SBOM.
type nestingProbe struct {
	// tempDir, when set, is where extraction work directories live, so each visit can record which
	// archives were overflowed to disk while they were all still held.
	tempDir string

	mu     sync.Mutex
	visits []nestingVisit
}

// entryStorageFiles are the basenames internal/archive gives the file one archive's entries are stored
// in. Which appears depends on the resolver under test, not on the routing this probe reports.
var entryStorageFiles = []string{"contents.tar", "contents.blob"}

func Test_mixedFamilyNesting_leafIsCatalogedOnceWithTheFullChain(t *testing.T) {
	// family order must not change the result: the same package, addressed by a chain naming its own
	// containers in its own order
	for _, row := range nestingRows() {
		t.Run(row.name, func(t *testing.T) {
			scanDir := t.TempDir()
			nested := writeNestedArchive(t, scanDir, nestPlan{families: row.families, leaf: markerLeaf()})

			probe := &nestingProbe{}
			s := scanDirWith(t, scanDir, nestingScanConfig(3, markerCataloger{}, probe))

			assert.Equal(t, 1, packageCount(s, "marker-pkg"), "%s: the leaf package must be cataloged exactly once", row.why)

			locs := leafLocations(s)
			require.Len(t, locs, 1, "the leaf must be reached by exactly one path")
			// exact, never a substring: a partially composed chain passes a substring check
			assert.Equal(t, nested.leafFileSystemID(), locs[0].ArchivePath,
				"the chain must name all three archives outer-to-inner")
			assert.Equal(t, "nested/marker.txt", locs[0].RealPath,
				"the path stays relative to the archive the file came from")

			assert.Equal(t, nested.fileSystemIDs, probe.archiveFileSystemIDs(),
				"every level must be cataloged, outer to inner, whatever families they are")
		})
	}
}

func Test_mixedFamilyNesting_containsEdgesChainAtEveryLevel(t *testing.T) {
	// the edges make the chain navigable in the SBOM and key on coordinates the file catalogers
	// recorded, so file cataloging has to be on for the inner archives to have any
	for _, row := range nestingRows() {
		t.Run(row.name, func(t *testing.T) {
			scanDir := t.TempDir()
			nested := writeNestedArchive(t, scanDir, nestPlan{families: row.families, leaf: markerLeaf()})

			cfg := withFileCataloging(nestingScanConfig(3, markerCataloger{}))
			s := scanDirWith(t, scanDir, cfg)

			// each archive's coordinates as seen in its parent; the outermost sits in the scanned
			// directory, so it carries no filesystem id of its own
			archiveCoords := make([]file.Coordinates, len(row.families))
			for i := range row.families {
				var parentFSID string
				if i > 0 {
					parentFSID = nested.fileSystemIDs[i-1]
				}
				archiveCoords[i] = file.Coordinates{RealPath: nested.paths[i], ArchivePath: parentFSID}
			}

			fileEdges := strset.New()
			pkgEdges := strset.New()
			for _, rel := range s.Relationships {
				if rel.Type != artifact.ContainsRelationship {
					continue
				}
				from, ok := rel.From.(file.Coordinates)
				if !ok {
					continue
				}
				switch to := rel.To.(type) {
				case file.Coordinates:
					fileEdges.Add(coordKey(from) + " -> " + coordKey(to))
				case pkg.Package:
					pkgEdges.Add(coordKey(from) + " -> " + to.Name)
				}
			}

			for i := 0; i < len(archiveCoords)-1; i++ {
				assert.True(t, fileEdges.Has(coordKey(archiveCoords[i])+" -> "+coordKey(archiveCoords[i+1])),
					"expected a CONTAINS edge from %s to %s", nested.paths[i], nested.paths[i+1])
			}

			innermost := archiveCoords[len(archiveCoords)-1]
			assert.True(t, pkgEdges.Has(coordKey(innermost)+" -> marker-pkg"),
				"expected a CONTAINS edge from %s to the leaf package", nested.paths[len(nested.paths)-1])
			assert.True(t, fileEdges.Has(coordKey(innermost)+" -> "+coordKey(file.Coordinates{
				RealPath:    "nested/marker.txt",
				ArchivePath: nested.leafFileSystemID(),
			})), "expected a CONTAINS edge from the innermost archive to the leaf file")
		})
	}
}

func Test_mixedFamilyNesting_javaLeafVirtualPathIsTheColonJoinedChain(t *testing.T) {
	// these colon-delimited strings are in already-published SBOMs, so a jar reached through three
	// levels of mixed families must still be reported under the chain of all three
	for _, row := range nestingRows() {
		if row.families[len(row.families)-1] != familyJar {
			continue
		}
		t.Run(row.name, func(t *testing.T) {
			scanDir := t.TempDir()
			nested := writeNestedArchive(t, scanDir, nestPlan{families: row.families, leaf: markerLeaf()})

			s := scanDirWith(t, scanDir, nestingScanConfig(3, markerCataloger{}))

			// the innermost archive is the jar, so its own package is the java leaf and the chain of
			// all three archives is exactly its virtual path
			leaf := fmt.Sprintf("level%d", len(row.families)-1)
			assert.Equal(t, 1, packageCount(s, leaf), "the leaf jar must be cataloged exactly once")
			assert.Equal(t, nested.virtualPaths[len(row.families)-1], javaVirtualPaths(s)[leaf])
		})
	}
}

func Test_mixedFamilyNesting_jarIsExercisedAsAContainer(t *testing.T) {
	// two mechanisms meet a jar: the java cataloger catalogs it as a package, the archive task descends
	// into it. A jar mid-chain must do both, exactly once each; the failure mode is a duplicate, not an
	// error.
	for _, row := range nestingRows() {
		var containerLevels []int
		for i, family := range row.families {
			if family == familyJar && i < len(row.families)-1 {
				containerLevels = append(containerLevels, i)
			}
		}
		if len(containerLevels) == 0 {
			continue
		}

		t.Run(row.name, func(t *testing.T) {
			scanDir := t.TempDir()
			nested := writeNestedArchive(t, scanDir, nestPlan{families: row.families, leaf: markerLeaf()})

			probe := &nestingProbe{}
			s := scanDirWith(t, scanDir, nestingScanConfig(3, markerCataloger{}, probe))

			for _, level := range containerLevels {
				name := fmt.Sprintf("level%d", level)
				assert.Equal(t, 1, packageCount(s, name),
					"the container jar's own package must be cataloged exactly once")
				assert.Equal(t, nested.virtualPaths[level], javaVirtualPaths(s)[name],
					"the container jar's virtual path must be its own place in the chain")
			}

			// and the archive task still descended through it, so the chain is complete below it
			assert.Equal(t, nested.fileSystemIDs, probe.archiveFileSystemIDs())
			locs := leafLocations(s)
			require.Len(t, locs, 1)
			assert.Equal(t, nested.leafFileSystemID(), locs[0].ArchivePath)
		})
	}
}

func Test_mixedFamilyNesting_depthCountsLevelsNotFamilies(t *testing.T) {
	// two rows with different families at every level, so the bound is shown not to turn on which
	// families are involved
	for _, row := range nestingRows()[:2] {
		t.Run(row.name, func(t *testing.T) {
			scanDir := t.TempDir()
			nested := writeNestedArchive(t, scanDir, nestPlan{families: row.families, leaf: markerLeaf()})

			probe := &nestingProbe{}
			cfg := withFileCataloging(nestingScanConfig(2, markerCataloger{}, probe))
			s := scanDirWith(t, scanDir, cfg)

			assert.Equal(t, nested.fileSystemIDs[:2], probe.archiveFileSystemIDs(),
				"at depth 2 the outer and middle archives are cataloged and the innermost is not")
			assert.Zero(t, packageCount(s, "marker-pkg"),
				"the leaf is one level past the bound, so its package must be absent")

			// the innermost archive is still cataloged as a file, inside the middle archive
			innermost := file.Coordinates{
				RealPath:    nested.paths[2],
				ArchivePath: nested.fileSystemIDs[1],
			}
			_, ok := s.Artifacts.FileMetadata[innermost]
			assert.True(t, ok, "the undescended archive must still be recorded as a file at %s", coordKey(innermost))
		})
	}
}

func Test_mixedFamilyNesting_defaultBoundsCatalogEveryRow(t *testing.T) {
	// the default bounds, pinned along with the fact that a three-level chain of any family mix sits
	// well inside them
	bounds := cataloging.DefaultArchiveSearchConfig()
	require.Equal(t, int64(2*1024*1024*1024), bounds.MaxMemoryBytes)
	require.Equal(t, int64(100*1024*1024*1024), bounds.MaxDiskBytes)

	for _, row := range nestingRows() {
		t.Run(row.name, func(t *testing.T) {
			scanDir := t.TempDir()
			nested := writeNestedArchive(t, scanDir, nestPlan{families: row.families, leaf: markerLeaf()})

			probe := &nestingProbe{}
			s := scanDirWith(t, scanDir, nestingScanConfig(3, markerCataloger{}, probe))

			assert.Equal(t, nested.fileSystemIDs, probe.archiveFileSystemIDs(),
				"every level of the chain must be cataloged at the default bounds")
			locs := leafLocations(s)
			require.Len(t, locs, 1)
			assert.Equal(t, nested.leafFileSystemID(), locs[0].ArchivePath)
		})
	}
}

func Test_mixedFamilyNesting_memoryPressureOverflowsRatherThanFailing(t *testing.T) {
	// memory pressure degrades to disk: an archive that will not fit spills rather than being refused,
	// and the memory limit alone decides where that boundary falls
	scanDir := t.TempDir()
	tempDir := isolatedTempDir(t)
	nested := writeNestedArchive(t, scanDir, gradedChain())

	t.Run("with a generous memory limit nothing overflows", func(t *testing.T) {
		probe := &nestingProbe{tempDir: tempDir}
		cfg := nestingScanConfig(3, markerCataloger{}, probe)
		// all three levels are held at once at the deepest point, so the limit must admit their sum
		generous := int64(nested.sizes[0]+nested.sizes[1]+nested.sizes[2]) + 1
		cfg = cfg.WithArchiveConfig(cfg.Archive.WithMaxMemoryBytes(generous))
		scanDirWith(t, scanDir, cfg)

		deepest := probe.deepestVisit()
		require.Equal(t, 3, deepest.depth, "the sample must be taken with all three levels still held")
		assert.Empty(t, deepest.overflowed, "with room in memory for every level, nothing is written to disk")
	})

	t.Run("a memory limit the outermost archive does not fit in", func(t *testing.T) {
		// only the outermost archive is routed by the memory limit, being the one whose bytes are copied
		// out of the scanned filesystem. Every archive below it is already an entry of its parent's store
		// and is read where it lies, taking neither memory nor a second copy. This pins the remaining
		// half: too large for memory means spilled, not failed, with the same outcome as a run with room.
		probe := &nestingProbe{tempDir: tempDir}
		cfg := nestingScanConfig(3, markerCataloger{}, probe)
		cfg = cfg.WithArchiveConfig(cfg.Archive.
			WithMaxMemoryBytes(int64(nested.sizes[2])).
			WithMaxDiskBytes(-1)) // unbounded: the disk limit must not be what decides anything here
		s := scanDirWith(t, scanDir, cfg)

		deepest := probe.deepestVisit()
		require.Equal(t, 3, deepest.depth, "the sample must be taken with all three levels still held")
		require.Less(t, int64(nested.sizes[2]), int64(nested.sizes[0]),
			"the outermost archive must be the one that does not fit, or this case asserts nothing")
		assert.Equal(t, []string{"level0.tar.gz"}, deepest.overflowed,
			"the archive that does not fit in memory spills rather than failing, and the levels inside "+
				"it are read where they lie rather than being copied anywhere")

		// and the outcome is identical to the default-bounds run
		assert.Equal(t, nested.fileSystemIDs, probe.archiveFileSystemIDs())
		locs := leafLocations(s)
		require.Len(t, locs, 1)
		assert.Equal(t, nested.leafFileSystemID(), locs[0].ArchivePath)
	})
}

func Test_mixedFamilyNesting_aNestedArchiveIsReadWhereItLies(t *testing.T) {
	// a nested archive is an entry of its parent's store, already charged to that parent, and its reader
	// supports Read, Seek and ReadAt - everything a zip's central directory needs - so it is handed to
	// the archive format where it lies. Nothing is copied, so nothing competes for the memory limit.
	//
	// Asserted at both ends of that limit: generous or zero, the nested levels neither hold memory nor
	// put a second copy of themselves on disk, and the whole chain is cataloged either way.
	scanDir := t.TempDir()
	tempDir := isolatedTempDir(t)
	nested := writeNestedArchive(t, scanDir, gradedChain())

	for _, tc := range []struct {
		name               string
		memoryBytes        int64
		outerAlsoOverflows bool
	}{
		{
			name:        "with room in memory for the outermost archive",
			memoryBytes: int64(nested.sizes[0]),
		},
		{
			name:               "with a memory limit of zero, so even the outermost overflows",
			memoryBytes:        0,
			outerAlsoOverflows: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := &nestingProbe{tempDir: tempDir}
			cfg := nestingScanConfig(3, markerCataloger{}, probe)
			cfg = cfg.WithArchiveConfig(cfg.Archive.
				WithMaxMemoryBytes(tc.memoryBytes).
				WithMaxDiskBytes(-1)) // unbounded: only the memory limit is under test

			s := scanDirWith(t, scanDir, cfg)

			deepest := probe.deepestVisit()
			require.Equal(t, 3, deepest.depth, "the sample must be taken with all three levels still held")

			var want []string
			if tc.outerAlsoOverflows {
				want = []string{"level0.tar.gz"}
			}
			assert.Equal(t, want, deepest.overflowed,
				"no copy of a nested archive is written anywhere: level1.zip and level2.jar are read "+
					"out of the tar of the archive holding them")

			assert.Equal(t, nested.fileSystemIDs, probe.archiveFileSystemIDs(),
				"and every level is still cataloged")
			locs := leafLocations(s)
			require.Len(t, locs, 1)
			assert.Equal(t, nested.leafFileSystemID(), locs[0].ArchivePath)
		})
	}
}

func Test_mixedFamilyNesting_diskLimitSkipsTheLevelItCannotAdmit(t *testing.T) {
	// the disk limit is terminal and the walk descends before it unwinds, so when the innermost level
	// cannot be admitted the outer and middle archives still hold everything they took: that level is
	// skipped, the shallower ones keep what they found, and the scan finishes. An implementation that
	// waited for capacity would deadlock, hence the timeout.
	scanDir := t.TempDir()
	tempDir := isolatedTempDir(t)
	nested := writeNestedArchive(t, scanDir, deepChain())

	// a sibling of a different family, to show the bound is per archive: it is processed once the chain
	// has been released, so it is cataloged in full
	require.NoError(t, os.WriteFile(
		filepath.Join(scanDir, "sibling.tgz"),
		buildTarGzBytes(t, map[string][]byte{"nested/marker.txt": []byte("sibling")}),
		0o644,
	))

	// the limit is measured rather than computed: what the chain holds on disk at a given level is a
	// fact about this corpus, so the chain runs once with no disk ceiling and the probe reports what was
	// on disk while two levels were held.
	//
	// The real run gets that figure with no slack, making this a skip rather than a truncation. Entries
	// are stored without framing, so any slack would admit some of the innermost level's content, and an
	// archive that stored some entries is truncated instead - covered elsewhere.
	measuring := &nestingProbe{tempDir: tempDir}
	measureCfg := nestingScanConfig(3, markerCataloger{}, measuring)
	measureCfg = measureCfg.WithArchiveConfig(measureCfg.Archive.WithMaxMemoryBytes(0).WithMaxDiskBytes(-1))
	scanDirWith(t, scanDir, measureCfg)

	twoLevelsHeld := measuring.visitAtDepth(2).diskBytes
	require.Positive(t, twoLevelsHeld, "the measuring run must have reached the second level")
	diskLimit := twoLevelsHeld

	probe := &nestingProbe{}
	cfg := nestingScanConfig(3, markerCataloger{}, probe)
	cfg = cfg.WithArchiveConfig(cfg.Archive.
		WithMaxMemoryBytes(0). // every archive spills, so its own bytes are charged to disk
		WithMaxDiskBytes(diskLimit))

	logs := captureLogs(t)
	s := scanWithinTimeout(t, scanDir, cfg, 60*time.Second)

	want := append(append([]string{}, nested.fileSystemIDs[:2]...), "sibling.tgz")
	assert.ElementsMatch(t, want, probe.archiveFileSystemIDs(),
		"the level that would exceed the limit is skipped, the shallower ones are still cataloged, "+
			"and a sibling of another family is unaffected")

	// the skip names the archive that triggered it, not just the bound
	assert.True(t, logs.sawFields(map[string]any{
		"archive": nested.paths[2],
		"limit":   diskLimit,
	}), "the skip must be attributed to the archive that reached the limit; saw %v", logs.eventsWith("archive"))

	fsIDs := strset.New()
	for _, loc := range leafLocations(s) {
		fsIDs.Add(loc.ArchivePath)
	}
	assert.False(t, fsIDs.Has(nested.leafFileSystemID()), "the skipped level's contents must be absent")
	assert.True(t, fsIDs.Has("sibling.tgz"), "the sibling of a different family must be cataloged fully")
}

func Test_mixedFamilyNesting_unboundedLimitsEnforceNothing(t *testing.T) {
	// a caller can opt out of one bound without the other, and opting out of both must still find the
	// deepest leaf. Both opt out with a negative value, since zero means "none of that resource".
	for _, row := range nestingRows() {
		t.Run(row.name, func(t *testing.T) {
			scanDir := t.TempDir()
			nested := writeNestedArchive(t, scanDir, nestPlan{families: row.families, leaf: markerLeaf()})

			probe := &nestingProbe{}
			cfg := nestingScanConfig(3, markerCataloger{}, probe)
			cfg = cfg.WithArchiveConfig(cfg.Archive.
				WithMaxMemoryBytes(-1).
				WithMaxDiskBytes(-1))

			s := scanWithinTimeout(t, scanDir, cfg, 60*time.Second)

			assert.Equal(t, nested.fileSystemIDs, probe.archiveFileSystemIDs())
			locs := leafLocations(s)
			require.Len(t, locs, 1)
			assert.Equal(t, nested.leafFileSystemID(), locs[0].ArchivePath)
		})
	}
}

func Test_mixedFamilyNesting_bothLimitsZeroSkipsEveryArchive(t *testing.T) {
	// the degenerate but well-defined configuration where nothing is admitted anywhere: unlike negative
	// (unbounded), zero on both limits skips every archive, and the scan still succeeds rather than
	// failing or finding anything inside the archives
	for _, row := range nestingRows() {
		t.Run(row.name, func(t *testing.T) {
			scanDir := t.TempDir()
			writeNestedArchive(t, scanDir, nestPlan{families: row.families, leaf: markerLeaf()})

			probe := &nestingProbe{}
			cfg := nestingScanConfig(3, markerCataloger{}, probe)
			cfg = cfg.WithArchiveConfig(cfg.Archive.
				WithMaxMemoryBytes(0).
				WithMaxDiskBytes(0))

			s := scanWithinTimeout(t, scanDir, cfg, 60*time.Second)

			assert.Empty(t, probe.archiveFileSystemIDs(), "no archive content can be admitted anywhere")
			assert.Empty(t, leafLocations(s), "the leaf is never reached since every archive is skipped")
		})
	}
}

// A skip is reported by a log line alone - reaching a bound must not fail the scan - so asserting the
// attribution means capturing what was logged. cmd/syft/internal/ui/log_writer_test.go uses the same
// log.Set/log.Get pair; this adds the field-carrying half, where the attribution lives.

// logCapture collects the field-carrying log events emitted while it is installed.
type logCapture struct {
	mu        sync.Mutex
	collected []map[string]any
}

// captureLogs installs a capturing logger for the test and restores the previous one afterwards.
func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	capture := &logCapture{}
	previous := log.Get()
	t.Cleanup(func() { log.Set(previous) })
	log.Set(&capturingLogger{Logger: discard.New(), capture: capture})
	return capture
}

func (c *logCapture) record(event map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collected = append(c.collected, event)
}

func (c *logCapture) events() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]any(nil), c.collected...)
}

// eventsWith is the captured events carrying the given field. A scan logs thousands of lines, so a
// failure message shows this subset rather than all of them.
func (c *logCapture) eventsWith(field string) []map[string]any {
	var out []map[string]any
	for _, event := range c.events() {
		if _, ok := event[field]; ok {
			out = append(out, event)
		}
	}
	return out
}

// sawFields reports whether any captured event carried every given field with exactly the given
// value.
func (c *logCapture) sawFields(want map[string]any) bool {
	for _, got := range c.events() {
		matched := true
		for key, value := range want {
			if !reflect.DeepEqual(got[key], value) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// capturingLogger discards every message but records the fields attached to those that carry any.
// Nested is left to the embedded discard logger, since nothing under test uses it.
type capturingLogger struct {
	logger.Logger
	capture *logCapture
}

func (l *capturingLogger) WithFields(fields ...any) logger.MessageLogger {
	return &capturingMessageLogger{
		MessageLogger: l.Logger.WithFields(fields...),
		capture:       l.capture,
		fields:        fieldMap(fields),
	}
}

type capturingMessageLogger struct {
	logger.MessageLogger
	capture *logCapture
	fields  map[string]any
}

func (l *capturingMessageLogger) emit(message string) {
	event := map[string]any{"message": message}
	for key, value := range l.fields {
		event[key] = value
	}
	l.capture.record(event)
}

func (l *capturingMessageLogger) Error(args ...any) { l.emit(fmt.Sprint(args...)) }
func (l *capturingMessageLogger) Warn(args ...any)  { l.emit(fmt.Sprint(args...)) }
func (l *capturingMessageLogger) Info(args ...any)  { l.emit(fmt.Sprint(args...)) }
func (l *capturingMessageLogger) Debug(args ...any) { l.emit(fmt.Sprint(args...)) }
func (l *capturingMessageLogger) Trace(args ...any) { l.emit(fmt.Sprint(args...)) }

func (l *capturingMessageLogger) Errorf(format string, args ...any) {
	l.emit(fmt.Sprintf(format, args...))
}
func (l *capturingMessageLogger) Warnf(format string, args ...any) {
	l.emit(fmt.Sprintf(format, args...))
}
func (l *capturingMessageLogger) Infof(format string, args ...any) {
	l.emit(fmt.Sprintf(format, args...))
}
func (l *capturingMessageLogger) Debugf(format string, args ...any) {
	l.emit(fmt.Sprintf(format, args...))
}
func (l *capturingMessageLogger) Tracef(format string, args ...any) {
	l.emit(fmt.Sprintf(format, args...))
}

// fieldMap turns the alternating key/value form log.WithFields takes into a map, folding in any
// logger.Fields passed as a whole.
func fieldMap(fields []any) map[string]any {
	out := map[string]any{}
	for i := 0; i < len(fields); i++ {
		if asMap, ok := fields[i].(logger.Fields); ok {
			for key, value := range asMap {
				out[key] = value
			}
			continue
		}
		key, ok := fields[i].(string)
		if !ok || i+1 >= len(fields) {
			continue
		}
		out[key] = fields[i+1]
		i++
	}
	return out
}

// pack builds one archive of this family holding the given entries.
func (f archiveFamily) pack(t *testing.T, base string, entries map[string][]byte) []byte {
	t.Helper()
	switch f {
	case familyZip:
		return buildZipBytesRaw(t, entries)
	case familyJar:
		// a manifest makes it a real jar to the java cataloger at any level; the package java reports is
		// named after the file, not the manifest title
		return jarBytes(t, base, "1.0", entries)
	case familyTar:
		return buildTarBytes(t, entries)
	case familyTarGz, familyTgz:
		return buildTarGzBytes(t, entries)
	}
	t.Fatalf("unknown archive family %q", f)
	return nil
}

// leafFileSystemID is the chain the innermost archive's contents carry: every archive, outer to
// inner. Assert it exactly, never as a substring: a partially composed chain passes a substring check.
func (n nestedArchive) leafFileSystemID() string {
	return n.fileSystemIDs[len(n.fileSystemIDs)-1]
}

// buildNestedArchive builds one archive per family given, each holding the next, with leaf inside
// the innermost.
func buildNestedArchive(t *testing.T, plan nestPlan) nestedArchive {
	t.Helper()
	require.NotEmpty(t, plan.families, "a chain needs at least one level")

	out := nestedArchive{
		sizes:         make([]int, len(plan.families)),
		paths:         make([]string, len(plan.families)),
		fileSystemIDs: make([]string, len(plan.families)),
		virtualPaths:  make([]string, len(plan.families)),
	}

	// the level index goes in every name and path segment, so no two levels share a path and a chain
	// assertion cannot pass on a value composed from the wrong level
	for i, family := range plan.families {
		base := fmt.Sprintf("level%d", i)
		if i == 0 {
			out.paths[i] = base + string(family)
			continue
		}
		out.paths[i] = fmt.Sprintf("nest%d/%s%s", i, base, family)
	}

	out.name = out.paths[0]
	for i := range plan.families {
		if i == 0 {
			out.fileSystemIDs[i] = out.paths[0]
			out.virtualPaths[i] = out.paths[0]
			continue
		}
		out.fileSystemIDs[i] = out.fileSystemIDs[i-1] + ":" + out.paths[i]
		out.virtualPaths[i] = out.virtualPaths[i-1] + ":" + out.paths[i]
	}

	// built innermost first, because each level's bytes are an entry of the level above it
	var packed []byte
	for i := len(plan.families) - 1; i >= 0; i-- {
		entries := map[string][]byte{}
		if i == len(plan.families)-1 {
			for name, body := range plan.leaf {
				entries[name] = body
			}
		} else {
			entries[out.paths[i+1]] = packed
		}
		for name, body := range plan.extra[i] {
			entries[name] = body
		}
		packed = plan.families[i].pack(t, fmt.Sprintf("level%d", i), entries)
		out.sizes[i] = len(packed)
	}
	out.bytes = packed

	return out
}

// writeNestedArchive writes the chain's outermost archive into dir and returns the chain.
func writeNestedArchive(t *testing.T, dir string, plan nestPlan) nestedArchive {
	t.Helper()
	nested := buildNestedArchive(t, plan)
	require.NoError(t, os.WriteFile(filepath.Join(dir, nested.name), nested.bytes, 0o644))
	return nested
}

// markerLeaf is the family-agnostic leaf payload: one file no archive format has an opinion about,
// found by markerCataloger. It keeps the rows comparable - the same package must come out whichever
// families the chain is made of.
func markerLeaf() map[string][]byte {
	return map[string][]byte{"nested/marker.txt": []byte("leaf")}
}

// incompressibleBytes returns n bytes deflate and gzip cannot shrink, so per-level sizes are
// predictable enough to place a bound between two of them.
func incompressibleBytes(n int) []byte {
	b := make([]byte, n)
	x := uint32(0x9e3779b9)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	return b
}

// nestingRows is the depth-3 matrix. Each row covers a case the others do not.
func nestingRows() []nestingRow {
	return []nestingRow{
		{
			name:     "tar.gz/zip/jar",
			families: []archiveFamily{familyTarGz, familyZip, familyJar},
			why:      "the headline case: compressed tar outermost, jar innermost",
		},
		{
			name:     "zip/tar.gz/jar",
			families: []archiveFamily{familyZip, familyTarGz, familyJar},
			why:      "compressed tar in the middle, where the stream-only format is not the entry point",
		},
		{
			name:     "jar/tar/zip",
			families: []archiveFamily{familyJar, familyTar, familyZip},
			why:      "jar as a container rather than a payload",
		},
		{
			name:     "tgz/tar/jar",
			families: []archiveFamily{familyTgz, familyTar, familyJar},
			why:      "the .tgz alias resolving at a non-outermost boundary",
		},
		{
			name:     "tar/jar/tar.gz",
			families: []archiveFamily{familyTar, familyJar, familyTarGz},
			why:      "compressed tar as the innermost, which nothing else covers",
		},
	}
}

func (p *nestingProbe) Name() string { return "nesting-probe" }

func (p *nestingProbe) Catalog(ctx context.Context, _ file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	trav := archive.TraversalFromContext(ctx)
	visit := nestingVisit{}
	if trav != nil {
		visit.virtualPath = trav.VirtualPath
		visit.depth = strings.Count(trav.VirtualPath, ":") + 1
	}
	if lim := archive.LimiterFromContext(ctx); lim != nil {
		_, visit.diskBytes = lim.InUse()
	}
	if p.tempDir != "" {
		visit.overflowed = overflowArchives(p.tempDir)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.visits = append(p.visits, visit)
	return nil, nil, nil
}

// archiveFileSystemIDs is the chain of every archive whose contents were cataloged, in visit order,
// with the scan root dropped.
func (p *nestingProbe) archiveFileSystemIDs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, v := range p.visits {
		if v.virtualPath == "" {
			continue
		}
		out = append(out, v.virtualPath)
	}
	return out
}

// visitAtDepth is the visit at the given nesting depth, for a case measuring what a run held while a
// particular level was being cataloged.
func (p *nestingProbe) visitAtDepth(depth int) nestingVisit {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, v := range p.visits {
		if v.depth == depth {
			return v
		}
	}
	return nestingVisit{}
}

// deepestVisit is the visit at the innermost level reached, the only moment at which every level of a
// chain is still held and its routing observable. It returns the whole visit so a case can also assert
// it got as deep as it meant to: an empty overflow sample from a visit that never left the scan root
// would otherwise read as "nothing overflowed".
func (p *nestingProbe) deepestVisit() nestingVisit {
	p.mu.Lock()
	defer p.mu.Unlock()
	var best nestingVisit
	for _, v := range p.visits {
		if v.depth > best.depth {
			best = v
		}
	}
	return best
}

// overflowArchives names the archive files in the live extraction work directories under tempDir.
// Content held in memory writes nothing there; content spilled to disk is written beside the archive's
// logical root under the archive's own name, which makes the routing observable without a hook into
// the limiter. Meaningful only while the archives are still held, so it is sampled from inside the
// sub-pipeline rather than after the scan.
//
// The file an archive's entries are stored in is skipped: it says nothing about where the archive's
// own bytes were routed.
func overflowArchives(tempDir string) []string {
	var out []string
	forEachHeldFile(tempDir, func(name string, _ os.FileInfo) {
		if isEntryStorageFile(name) {
			return
		}
		out = append(out, name)
	})
	sort.Strings(out)
	return out
}

func isEntryStorageFile(name string) bool {
	for _, storage := range entryStorageFiles {
		if name == storage {
			return true
		}
	}
	return false
}

// forEachHeldFile visits every file an archive work directory is holding, wherever under tempDir those
// directories were created. It walks the tree rather than reading one level, since an archive's work
// directory sits under the scan's own temp root (internal/tmpdir), whose name this probe does not
// choose.
func forEachHeldFile(tempDir string, visit func(name string, info os.FileInfo)) {
	_ = filepath.WalkDir(tempDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || !strings.HasPrefix(d.Name(), "syft-archive-") {
			return nil //nolint:nilerr // an unreadable directory holds nothing this probe can report
		}
		held, err := os.ReadDir(path)
		if err != nil {
			return filepath.SkipDir
		}
		for _, entry := range held {
			if entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			visit(entry.Name(), info)
		}
		return filepath.SkipDir
	})
}

// isolatedTempDir points archive extraction at a directory of this test's own, so an overflow sample
// sees only this scan's work directories.
func isolatedTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	require.Equal(t, dir, os.TempDir(), "extraction must be writing where the probe is looking")
	return dir
}

// nestingScanConfig selects the java catalogers - so a jar is met as a jar wherever it sits - and
// always runs the given catalogers. Selected by tag rather than the whole default set, which includes
// the RPM cataloger and its sqlite driver this test binary does not register.
func nestingScanConfig(depth int, catalogers ...pkg.Cataloger) *CreateSBOMConfig {
	cfg := DefaultCreateSBOMConfig().
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults("java"))
	for _, c := range catalogers {
		cfg = cfg.WithCatalogers(pkgcataloging.NewAlwaysEnabledCatalogerReference(c))
	}
	return cfg.WithArchiveConfig(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(depth))
}

// withFileCataloging turns on file cataloging, which the CONTAINS chain needs: archive-to-file edges
// key on coordinates the file catalogers recorded, so without them an inner archive has no coordinate
// to hang an edge on.
func withFileCataloging(cfg *CreateSBOMConfig) *CreateSBOMConfig {
	return cfg.WithFilesConfig(filecataloging.Config{Selection: file.AllFilesSelection})
}

func leafLocations(s *sbom.SBOM) []file.Location {
	var out []file.Location
	for _, p := range s.Artifacts.Packages.Sorted() {
		if p.Name != "marker-pkg" {
			continue
		}
		out = append(out, p.Locations.ToSlice()...)
	}
	return out
}

func javaVirtualPaths(s *sbom.SBOM) map[string]string {
	out := map[string]string{}
	for _, p := range s.Artifacts.Packages.Sorted() {
		if metadata, ok := p.Metadata.(pkg.JavaArchive); ok {
			out[p.Name] = metadata.VirtualPath
		}
	}
	return out
}

func packageCount(s *sbom.SBOM, name string) int {
	var n int
	for _, p := range s.Artifacts.Packages.Sorted() {
		if p.Name == name {
			n++
		}
	}
	return n
}

// scanWithinTimeout runs the scan on its own goroutine and fails if it has not finished in time.
//
// The depth-3 limit cases need it: the walk descends before it unwinds, so the outer and middle
// archives still hold their content when the inner one is refused. An implementation that waited for
// capacity would deadlock, and a test asserting only the result would hang rather than fail.
func scanWithinTimeout(t *testing.T, dir string, cfg *CreateSBOMConfig, timeout time.Duration) *sbom.SBOM {
	t.Helper()
	src, err := directorysource.New(directorysource.Config{Path: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	type outcome struct {
		s   *sbom.SBOM
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		s, err := cfg.Create(context.Background(), src)
		done <- outcome{s: s, err: err}
	}()

	select {
	case got := <-done:
		require.NoError(t, got.err, "reaching a bound must not fail the scan")
		return got.s
	case <-time.After(timeout):
		t.Fatalf("the scan did not finish within %s: reaching a limit must skip the archive that "+
			"reached it, never wait for capacity that nothing in the chain will release", timeout)
		return nil
	}
}

func coordKey(c file.Coordinates) string {
	return c.ArchivePath + "|" + c.RealPath
}

// gradedChain is the headline row with each level padded so the three archives have clearly different
// sizes: a container is never smaller than what it holds, so a bound can only be placed between two
// levels if they are graded on purpose.
func gradedChain() nestPlan {
	return nestPlan{
		families: []archiveFamily{familyTarGz, familyZip, familyJar},
		leaf:     markerLeaf(),
		extra: map[int]map[string][]byte{
			0: {"pad0.bin": incompressibleBytes(24 * 1024)},
			1: {"pad1.bin": incompressibleBytes(24 * 1024)},
			2: {"pad2.bin": incompressibleBytes(8 * 1024)},
		},
	}
}

// deepChain is the headline row with one large, incompressible payload at the leaf and no other
// padding. The payload dominates every level, so the three archives are about the same size, giving
// the disk limit arithmetic below slack of half an archive rather than a few hundred bytes.
func deepChain() nestPlan {
	return nestPlan{
		families: []archiveFamily{familyTarGz, familyZip, familyJar},
		leaf: map[string][]byte{
			"nested/marker.txt": []byte("leaf"),
			"payload.bin":       incompressibleBytes(64 * 1024),
		},
	}
}

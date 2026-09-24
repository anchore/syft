package task

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/sbom"
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
	// paths is each archive's path within its parent, outermost first; paths[0] is the outermost archive
	// as the scan's resolver reports it.
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
	// heldFiles are the spill files live at this moment, sampled only when the probe was given a temp
	// dir to look in. A nested archive's own bytes are read where they lie, so one appears per archive
	// whose entries did not fit in memory.
	heldFiles []string
}

// nestingProbe records one visit per filesystem the archive cataloger runs its sub-pipeline against,
// reading the chain off the traversal on the context.
type nestingProbe struct {
	// tempDir, when set, is where extraction work directories live
	tempDir string

	mu     sync.Mutex
	visits []nestingVisit
}

func Test_mixedFamilyNesting_leafIsCatalogedOnceWithTheFullChain(t *testing.T) {
	// family order must not change the result: the same package, addressed by a chain naming its own
	// containers in its own order
	for _, row := range nestingRows() {
		t.Run(row.name, func(t *testing.T) {
			scanDir := t.TempDir()
			nested := writeNestedArchive(t, scanDir, nestPlan{families: row.families, leaf: markerLeaf()})

			probe := &nestingProbe{}
			s := runNesting(t, scanDir, 3, defaultLimits(), markerTask(), probe.task())

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
	// the edges make the chain navigable in the SBOM. The archive-to-archive edges must not depend on
	// the file catalogers having recorded the inner archives, since the default file selection does not
	for _, row := range nestingRows() {
		t.Run(row.name, func(t *testing.T) {
			scanDir := t.TempDir()
			nested := writeNestedArchive(t, scanDir, nestPlan{families: row.families, leaf: markerLeaf()})

			s := runNesting(t, scanDir, 3, defaultLimits(), markerTask())

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

			// with file cataloging on, files inside an archive get an edge from it too
			s = runNesting(t, scanDir, 3, defaultLimits(), markerTask(), fileMetadataTask())
			var leafEdge bool
			for _, rel := range s.Relationships {
				from, _ := rel.From.(file.Coordinates)
				to, _ := rel.To.(file.Coordinates)
				leafEdge = leafEdge || (from == innermost && to == file.Coordinates{RealPath: "nested/marker.txt", ArchivePath: nested.leafFileSystemID()})
			}
			assert.True(t, leafEdge, "expected a CONTAINS edge from the innermost archive to the leaf file")
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

			s := runNesting(t, scanDir, 3, defaultLimits(), markerTask(), javaTask())

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
			s := runNesting(t, scanDir, 3, defaultLimits(), markerTask(), javaTask(), probe.task())

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
			s := runNesting(t, scanDir, 2, defaultLimits(), markerTask(), fileMetadataTask(), probe.task())

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

			// and what was left unexplored is said out loud, not silently dropped
			reasons := s.Artifacts.Unknowns[innermost]
			require.Len(t, reasons, 1, "unknowns: %v", s.Artifacts.Unknowns)
			assert.Contains(t, reasons[0], "depth limit was reached")
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
			s := runNesting(t, scanDir, 3, archiveLimits(bounds), markerTask(), probe.task())

			assert.Equal(t, nested.fileSystemIDs, probe.archiveFileSystemIDs(),
				"every level of the chain must be cataloged at the default bounds")
			locs := leafLocations(s)
			require.Len(t, locs, 1)
			assert.Equal(t, nested.leafFileSystemID(), locs[0].ArchivePath)
		})
	}
}

func Test_mixedFamilyNesting_memoryPressureOverflowsRatherThanFailing(t *testing.T) {
	// entries that will not fit in memory are written to disk rather than refused
	scanDir := t.TempDir()
	tempDir := isolatedTempDir(t)
	nested := writeNestedArchive(t, scanDir, gradedChain())

	t.Run("with a generous memory limit nothing is written to disk", func(t *testing.T) {
		probe := &nestingProbe{tempDir: tempDir}
		bounds := defaultLimits()
		bounds.MaxMemoryBytes = int64(2 * (nested.sizes[0] + nested.sizes[1] + nested.sizes[2]))
		runNesting(t, scanDir, 3, bounds, markerTask(), probe.task())

		deepest := probe.deepestVisit()
		require.Equal(t, 3, deepest.depth, "the sample must be taken with all three levels still held")
		assert.Empty(t, deepest.heldFiles)
	})

	t.Run("with a memory limit the outermost archive's entries do not fit in", func(t *testing.T) {
		// room for every level's index estimate, which must stay in memory, but not the outer entries
		probe := &nestingProbe{tempDir: tempDir}
		bounds := archive.Limits{MaxMemoryBytes: int64(nested.sizes[2] + 32*1024), MaxDiskBytes: -1}
		s := runNesting(t, scanDir, 3, bounds, markerTask(), probe.task())

		deepest := probe.deepestVisit()
		require.Equal(t, 3, deepest.depth, "the sample must be taken with all three levels still held")
		assert.Contains(t, deepest.heldFiles, "archive-spill", "entries that do not fit in memory are written to disk")

		assert.Equal(t, nested.fileSystemIDs, probe.archiveFileSystemIDs(), "and every level is still cataloged")
		locs := leafLocations(s)
		require.Len(t, locs, 1)
		assert.Equal(t, nested.leafFileSystemID(), locs[0].ArchivePath)
	})
}

func Test_mixedFamilyNesting_aNestedArchiveIsReadWhereItLies(t *testing.T) {
	// an archive's own bytes are read where they lie: a scanned file from disk, a nested archive from
	// its parent's entries. Nothing copies them, so at most one spill file per level appears whatever
	// the memory limit; only entries are held, and only they can be written out.
	scanDir := t.TempDir()
	tempDir := isolatedTempDir(t)
	nested := writeNestedArchive(t, scanDir, gradedChain())

	for _, tc := range []struct {
		name          string
		memoryBytes   int64
		wantHeldFiles []string
	}{
		{
			name:        "with room in memory for every level's entries",
			memoryBytes: int64(2 * (nested.sizes[0] + nested.sizes[1] + nested.sizes[2])),
		},
		{
			name:          "with a memory limit of zero, so every level's entries are written out",
			memoryBytes:   0,
			wantHeldFiles: []string{"archive-spill", "archive-spill", "archive-spill"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := &nestingProbe{tempDir: tempDir}
			bounds := archive.Limits{MaxMemoryBytes: tc.memoryBytes, MaxDiskBytes: -1}

			s := runNesting(t, scanDir, 3, bounds, markerTask(), probe.task())

			deepest := probe.deepestVisit()
			require.Equal(t, 3, deepest.depth, "the sample must be taken with all three levels still held")
			assert.Equal(t, tc.wantHeldFiles, deepest.heldFiles)

			assert.Equal(t, nested.fileSystemIDs, probe.archiveFileSystemIDs())
			locs := leafLocations(s)
			require.Len(t, locs, 1)
			assert.Equal(t, nested.leafFileSystemID(), locs[0].ArchivePath)
		})
	}
}

func Test_mixedFamilyNesting_diskLimitTruncatesTheLevelItCannotAdmit(t *testing.T) {
	// the walk descends before it unwinds, so the outer and middle archives still hold their entries
	// when the innermost level's do not fit in memory. With nothing admitted on disk that level is
	// cataloged from nothing, the shallower ones keep what they found, and the scan finishes. An
	// implementation that waited for capacity would deadlock, hence the timeout.
	scanDir := t.TempDir()
	nested := writeNestedArchive(t, scanDir, deepChain())

	// a sibling of a different family, processed once the chain has been released, so cataloged in full
	require.NoError(t, os.WriteFile(
		filepath.Join(scanDir, "sibling.tgz"),
		makeTarGz(t, map[string][]byte{"nested/marker.txt": []byte("sibling")}),
		0o644,
	))

	// room for the outer two levels' entries (each about the size of the archive it holds) but not the
	// innermost's payload, which is half an archive larger than the slack
	memoryLimit := int64(nested.sizes[0] + nested.sizes[1] + deepChainPayloadBytes/2)

	probe := &nestingProbe{}
	bounds := archive.Limits{MaxMemoryBytes: memoryLimit, MaxDiskBytes: 0}

	s := runNesting(t, scanDir, 3, bounds, markerTask(), probe.task())

	want := append(append([]string{}, nested.fileSystemIDs...), "/sibling.tgz")
	assert.ElementsMatch(t, want, probe.archiveFileSystemIDs(),
		"every level is visited, the truncated one with nothing inside it")

	fsIDs := strset.New()
	for _, loc := range leafLocations(s) {
		fsIDs.Add(loc.ArchivePath)
	}
	assert.False(t, fsIDs.Has(nested.leafFileSystemID()), "the truncated level's contents must be absent")
	assert.True(t, fsIDs.Has("/sibling.tgz"), "the sibling of a different family must be cataloged fully")

	var truncated []string
	for coords, reasons := range s.Artifacts.Unknowns {
		for _, reason := range reasons {
			if strings.Contains(reason, "disk limit") {
				truncated = append(truncated, coords.ArchivePath+":"+coords.RealPath)
			}
		}
	}
	assert.Equal(t, []string{nested.fileSystemIDs[1] + ":" + nested.paths[2]}, truncated,
		"the truncation is recorded against the archive that reached the limit")
}

func Test_mixedFamilyNesting_unboundedLimitsEnforceNothing(t *testing.T) {
	// a caller can opt out of one bound without the other, and opting out of both must still find the
	// deepest leaf. Both opt out with a negative value, since zero means the default.
	for _, row := range nestingRows() {
		t.Run(row.name, func(t *testing.T) {
			scanDir := t.TempDir()
			nested := writeNestedArchive(t, scanDir, nestPlan{families: row.families, leaf: markerLeaf()})

			probe := &nestingProbe{}
			bounds := archive.Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1}

			s := runNesting(t, scanDir, 3, bounds, markerTask(), probe.task())

			assert.Equal(t, nested.fileSystemIDs, probe.archiveFileSystemIDs())
			locs := leafLocations(s)
			require.Len(t, locs, 1)
			assert.Equal(t, nested.leafFileSystemID(), locs[0].ArchivePath)
		})
	}
}

func defaultLimits() archive.Limits {
	return archiveLimits(cataloging.DefaultArchiveSearchConfig())
}

// runNesting runs the archive cataloger task over scanDir with the given sub-pipeline and returns the
// SBOM it built. It runs on its own goroutine and fails if the task has not finished in time.
//
// The depth-3 limit cases need the timeout: the walk descends before it unwinds, so the outer and
// middle archives still hold their content when the inner one is refused. An implementation that
// waited for capacity would deadlock, and a test asserting only the result would hang rather than fail.
func runNesting(t *testing.T, scanDir string, depth int, bounds archive.Limits, subPipeline ...Task) *sbom.SBOM {
	t.Helper()
	tsk := newLimitedTestTask(t, depth, bounds, subPipeline...)
	s := &sbom.SBOM{Artifacts: sbom.Artifacts{
		Packages:     pkg.NewCollection(),
		FileMetadata: map[file.Coordinates]file.Metadata{},
	}}

	done := make(chan error, 1)
	go func() {
		done <- tsk.Execute(context.Background(), dirTestResolver{dir: scanDir}, sbomsync.NewBuilder(s))
	}()

	select {
	case err := <-done:
		require.NoError(t, err, "reaching a bound must not fail the scan")
		return s
	case <-time.After(60 * time.Second):
		t.Fatal("the scan did not finish in time: reaching a limit must skip the archive that " +
			"reached it, never wait for capacity that nothing in the chain will release")
		return nil
	}
}

// markerTask emits one package per "marker.txt" found, so the matrix asserts behavior without
// depending on any real cataloger's fixture format.
func markerTask() Task {
	return NewTask("marker-cataloger", func(_ context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		locations, err := resolver.FilesByGlob("**/marker.txt")
		if err != nil {
			return err
		}
		for _, loc := range locations {
			p := pkg.Package{
				Name:      "marker-pkg",
				Version:   "1.0.0",
				Type:      pkg.BinaryPkg,
				Locations: file.NewLocationSet(loc),
			}
			p.SetID()
			builder.AddPackages(p)
		}
		return nil
	})
}

// javaTask is the java archive cataloger as the cataloging factory builds it, so a jar is met as a jar
// wherever it sits in a chain.
func javaTask() Task {
	return NewPackageTask(CatalogingFactoryConfig{}, java.NewArchiveCataloger(java.DefaultArchiveCatalogerConfig()))
}

// fileMetadataTask records every file, so each file inside an archive gets an archive-to-file edge.
func fileMetadataTask() Task {
	return newFileMetadataCatalogerTask(file.AllFilesSelection)
}

// pack builds one archive of this family holding the given entries.
func (f archiveFamily) pack(t *testing.T, base string, entries map[string][]byte) []byte {
	t.Helper()
	switch f {
	case familyZip:
		return makeZip(t, entries)
	case familyJar:
		// a manifest makes it a real jar to the java cataloger at any level; the package java reports is
		// named after the file, not the manifest title
		return makeJar(t, base, "1.0", entries)
	case familyTar:
		return makeTar(t, entries)
	case familyTarGz, familyTgz:
		return makeTarGz(t, entries)
	}
	t.Fatalf("unknown archive family %q", f)
	return nil
}

func makeJar(t *testing.T, title, version string, extra map[string][]byte) []byte {
	t.Helper()
	entries := map[string][]byte{
		"META-INF/MANIFEST.MF": []byte(
			"Manifest-Version: 1.0\nImplementation-Title: " + title + "\nImplementation-Version: " + version + "\n",
		),
	}
	for k, v := range extra {
		entries[k] = v
	}
	return makeZip(t, entries)
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
			// the outermost archive is a file in the scanned directory, which the resolver reports rooted
			out.name = base + string(family)
			out.paths[i] = "/" + out.name
			continue
		}
		out.paths[i] = fmt.Sprintf("nest%d/%s%s", i, base, family)
	}

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
// found by markerTask. It keeps the rows comparable - the same package must come out whichever
// families the chain is made of.
func markerLeaf() map[string][]byte {
	return map[string][]byte{"nested/marker.txt": []byte("leaf")}
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

func (p *nestingProbe) task() Task {
	return NewTask("nesting-probe", func(ctx context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		trav := archive.TraversalFromContext(ctx)
		visit := nestingVisit{}
		if trav != nil {
			visit.virtualPath = archive.VirtualPath(trav.Location)
			visit.depth = strings.Count(archive.VirtualPath(trav.Location), ":") + 1
		}
		if p.tempDir != "" {
			visit.heldFiles = heldFiles(p.tempDir)
		}

		p.mu.Lock()
		defer p.mu.Unlock()
		p.visits = append(p.visits, visit)
		return nil
	})
}

// archiveFileSystemIDs is the chain of every archive whose contents were cataloged, in visit order.
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

// heldFiles names the spill files live under tempDir, one "archive-spill" per archive holding content
// that did not fit in memory. Meaningful only while the archives are still held, so it is sampled from
// inside the sub-pipeline rather than after the scan.
func heldFiles(tempDir string) (names []string) {
	_ = filepath.WalkDir(tempDir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasPrefix(d.Name(), "archive-") {
			return nil //nolint:nilerr // an unreadable directory holds nothing this probe can report
		}
		// the name is the pattern with os.CreateTemp's random suffix in place of the "*"
		names = append(names, d.Name()[:strings.LastIndexByte(d.Name(), '-')])
		return nil
	})
	sort.Strings(names)
	return names
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
			0: {"pad0.bin": incompressible(24 * 1024)},
			1: {"pad1.bin": incompressible(24 * 1024)},
			2: {"pad2.bin": incompressible(8 * 1024)},
		},
	}
}

// deepChainPayloadBytes is the size of deepChain's leaf payload.
const deepChainPayloadBytes = 64 * 1024

// deepChain is the headline row with one large, incompressible payload at the leaf and no other
// padding. The payload dominates every level, so the three archives are about the same size. It sorts
// before the marker so it is the first entry refused when the leaf archive's entries do not fit.
func deepChain() nestPlan {
	return nestPlan{
		families: []archiveFamily{familyTarGz, familyZip, familyJar},
		leaf: map[string][]byte{
			"0-payload.bin":     incompressible(deepChainPayloadBytes),
			"nested/marker.txt": []byte("leaf"),
		},
	}
}

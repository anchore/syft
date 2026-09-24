package task

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// dirTestResolver is a minimal file.Resolver over a directory. FilesByMIMEType sniffs each file's
// content as a real resolver does; FileContentsByLocation opens the file, which is random-access.
type dirTestResolver struct {
	file.Resolver
	dir  string
	fsid string
}

// streamingDirResolver is dirTestResolver handing out plain streams, so an archive's own bytes must be
// held in memory or written to disk rather than read in place.
type streamingDirResolver struct {
	dirTestResolver
}

func (d streamingDirResolver) FileContentsByLocation(loc file.Location) (io.ReadCloser, error) {
	f, err := d.dirTestResolver.FileContentsByLocation(loc)
	if err != nil {
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{f, f}, nil
}

// panickingDirResolver is dirTestResolver whose reads of one file panic, standing in for a decoder
// that panics on hostile bytes.
type panickingDirResolver struct {
	dirTestResolver
	path string
}

func (d panickingDirResolver) FileContentsByLocation(loc file.Location) (io.ReadCloser, error) {
	if loc.RealPath == d.path {
		return io.NopCloser(panicReader{}), nil
	}
	return d.dirTestResolver.FileContentsByLocation(loc)
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("decoder blew up") }

func Test_archiveCataloger_aPanicCostsOnlyThatArchive(t *testing.T) {
	rootDir := t.TempDir()
	for _, name := range []string{"bad.zip", "good.zip"} {
		require.NoError(t, os.WriteFile(filepath.Join(rootDir, name), makeZip(t, map[string][]byte{"a.txt": []byte("a")}), 0o600))
	}

	var seen []string
	tsk := newTestTask(t, cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1), capturingTask(t, &seen, nil))

	resolver := panickingDirResolver{dirTestResolver: dirTestResolver{dir: rootDir}, path: "/bad.zip"}
	err := tsk.Execute(context.Background(), resolver, sbomsync.NewBuilder(newTestSBOM()))

	// a coordinate error becomes an unknown; a plain error (or an escaped panic) would fail the scan
	coordErrs, remaining := unknown.ExtractCoordinateErrors(err)
	require.NoError(t, remaining)
	require.Len(t, coordErrs, 1)
	assert.Equal(t, "/bad.zip", coordErrs[0].Coordinates.RealPath)
	assert.ErrorContains(t, coordErrs[0].Reason, "panic while cataloging archive: decoder blew up")
	assert.Equal(t, []string{"/good.zip"}, seen, "the sibling is still cataloged")
}

func newTestTask(t *testing.T, cfg cataloging.ArchiveSearchConfig, subPipeline ...Task) Task {
	t.Helper()
	tsk := NewArchiveCatalogerTask(cfg, subPipeline, nil)
	require.NotNil(t, tsk)
	return tsk
}

// newLimitedTestTask builds the task with the limiter's own limits, where zero forbids the resource.
func newLimitedTestTask(t *testing.T, maxDepth int, limits archive.Limits, subPipeline ...Task) Task {
	t.Helper()
	tsk := newArchiveCatalogerTask(maxDepth, limits, subPipeline, nil)
	require.NotNil(t, tsk)
	return tsk
}

func newTestSBOM() *sbom.SBOM {
	return &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
}

func countingTask(ran *int) Task {
	return NewTask("count-runs", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		*ran++
		return nil
	})
}

// capturingTask records the virtual path of every archive the sub-pipeline is run against and how many
// files its resolver holds.
func capturingTask(t *testing.T, seen *[]string, fileCounts *map[string]int) Task {
	return NewTask("capture", func(ctx context.Context, r file.Resolver, _ sbomsync.Builder) error {
		trav := archive.TraversalFromContext(ctx)
		require.NotNil(t, trav)
		*seen = append(*seen, archive.VirtualPath(trav.Location))
		if fileCounts != nil {
			locs, err := r.FilesByGlob("**")
			require.NoError(t, err)
			(*fileCounts)[archive.VirtualPath(trav.Location)] = len(locs)
		}
		return nil
	})
}

func Test_archiveCataloger_traversalThreading(t *testing.T) {
	manifest := []byte("Manifest-Version: 1.0\nImplementation-Title: example\nImplementation-Version: 1.0.0\n")
	innerJar := makeZip(t, map[string][]byte{"META-INF/MANIFEST.MF": manifest})
	innerZip := makeZip(t, map[string][]byte{"README.txt": []byte("hi")})
	outerZip := makeZip(t, map[string][]byte{
		"lib/inner.jar":    innerJar,
		"nested/inner.zip": innerZip,
	})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	var seen []string
	tsk := newTestTask(t, cataloging.DefaultArchiveSearchConfig().WithMaxDepth(3), capturingTask(t, &seen, nil))

	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(newTestSBOM())))

	// java archives are traversed like any other archive when the task is enabled
	assert.ElementsMatch(t, []string{
		"/outer.zip",
		"/outer.zip:lib/inner.jar",
		"/outer.zip:nested/inner.zip",
	}, seen)
}

func Test_archiveCataloger_zeroLimitsMeanDefault(t *testing.T) {
	// a config literal naming only the depth must catalog archives, not forbid both memory and disk
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), makeZip(t, map[string][]byte{"a.txt": []byte("a")}), 0o600))

	var seen []string
	fileCounts := map[string]int{}
	tsk := newTestTask(t, cataloging.ArchiveSearchConfig{MaxDepth: 1}, capturingTask(t, &seen, &fileCounts))

	s := newTestSBOM()
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)))

	assert.Equal(t, []string{"/outer.zip"}, seen)
	assert.Equal(t, 1, fileCounts["/outer.zip"])
	assert.Empty(t, s.Artifacts.Unknowns)
}

func Test_archiveCataloger_truncationStillCatalogs(t *testing.T) {
	// reaching a limit is a truncation, not a failure: the sub-pipeline still runs over what was stored
	big := bytes.Repeat([]byte("x"), 4096)
	outerZip := makeZip(t, map[string][]byte{
		"a/small.txt": []byte("small"),
		"b/big.txt":   big,
	})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	// nothing is held in memory, so each entry is charged to disk: small.txt lands, big.txt is refused
	limits := archive.Limits{MaxMemoryBytes: 0, MaxDiskBytes: 6000}

	var seen []string
	fileCounts := map[string]int{}
	tsk := newLimitedTestTask(t, 1, limits, capturingTask(t, &seen, &fileCounts))

	s := newTestSBOM()
	err := tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s))

	require.NoError(t, err, "a truncated extraction must not fail the scan")
	assert.Equal(t, []string{"/outer.zip"}, seen, "the sub-pipeline must run over the partial contents")
	assert.Equal(t, 1, fileCounts["/outer.zip"], "only the entry stored before the limit is visible")

	reasons, ok := s.Artifacts.Unknowns[file.Coordinates{RealPath: "/outer.zip"}]
	require.True(t, ok, "the truncation must be recorded against the archive; got %v", s.Artifacts.Unknowns)
	require.Len(t, reasons, 1)
	assert.Contains(t, reasons[0], "archive cataloged from part of its contents")
	assert.Contains(t, reasons[0], ArchiveCatalogerTaskName, "the unknown names the task that recorded it")
}

func Test_archiveCataloger_failureIsRecordedAndSkipsSubPipeline(t *testing.T) {
	rootDir := t.TempDir()
	// entry data overwritten but header and end-of-central-directory intact: detected as an archive,
	// fails when the entry is read
	corrupt := makeZip(t, map[string][]byte{"data.bin": incompressible(4096)})
	require.Greater(t, len(corrupt), 1024)
	for i := 100; i < 600; i++ {
		corrupt[i] ^= 0xff
	}
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "corrupt.zip"), corrupt, 0o600))

	goodZip := makeZip(t, map[string][]byte{"ok.txt": []byte("ok")})
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "good.zip"), goodZip, 0o600))

	var ran int
	tsk := newTestTask(t, cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1), countingTask(&ran))

	err := tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(newTestSBOM()))

	// a coordinate error is what executor.go pulls out into sbom.Artifacts.Unknowns; a plain error would
	// fail the scan instead
	require.Error(t, err)
	coordErrs, remaining := unknown.ExtractCoordinateErrors(err)
	assert.NoError(t, remaining, "nothing may escape as a non-coordinate error")
	require.Len(t, coordErrs, 1)
	assert.Equal(t, "/corrupt.zip", coordErrs[0].Coordinates.RealPath)

	assert.Equal(t, 1, ran, "the sub-pipeline must still run for the archive that extracted cleanly")
}

func Test_NewArchiveCatalogerTask_gating(t *testing.T) {
	someTask := NewTask("noop", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error { return nil })

	tests := []struct {
		name        string
		cfg         cataloging.ArchiveSearchConfig
		subPipeline []Task
		wantTask    bool
	}{
		{
			name:        "disabled at depth 0",
			cfg:         cataloging.DefaultArchiveSearchConfig(),
			subPipeline: []Task{someTask},
		},
		{
			name:        "no sub-pipeline",
			cfg:         cataloging.DefaultArchiveSearchConfig().WithMaxDepth(2),
			subPipeline: nil,
		},
		{
			name:        "enabled",
			cfg:         cataloging.DefaultArchiveSearchConfig().WithMaxDepth(2),
			subPipeline: []Task{someTask},
			wantTask:    true,
		},
		{
			name:        "enabled at negative depth",
			cfg:         cataloging.DefaultArchiveSearchConfig().WithMaxDepth(-1),
			subPipeline: []Task{someTask},
			wantTask:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewArchiveCatalogerTask(tt.cfg, tt.subPipeline, nil)
			if tt.wantTask {
				require.NotNil(t, got)
				assert.Equal(t, ArchiveCatalogerTaskName, got.Name())
				return
			}
			assert.Nil(t, got)
		})
	}
}

func Test_archiveCataloger_depthBoundIsExact(t *testing.T) {
	innerZip := makeZip(t, map[string][]byte{"deep.txt": []byte("deep")})
	outerZip := makeZip(t, map[string][]byte{"nested/inner.zip": innerZip})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	run := func(t *testing.T, depth int) []string {
		t.Helper()
		var seen []string
		tsk := newTestTask(t, cataloging.DefaultArchiveSearchConfig().WithMaxDepth(depth), capturingTask(t, &seen, nil))
		require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(newTestSBOM())),
			"reaching the depth bound must not be an error")
		return seen
	}

	assert.Equal(t, []string{"/outer.zip"}, run(t, 1), "depth 1 catalogs the top-level archive and does not descend")
	assert.ElementsMatch(t, []string{"/outer.zip", "/outer.zip:nested/inner.zip"}, run(t, 2), "depth 2 descends one level")
}

func Test_NewArchiveCatalogerTask_dropsItselfFromSubPipeline(t *testing.T) {
	// a copy of itself in the sub-pipeline would process every nesting level twice
	cfg := cataloging.DefaultArchiveSearchConfig().WithMaxDepth(2)

	innerZip := makeZip(t, map[string][]byte{"leaf.txt": []byte("leaf")})
	outerZip := makeZip(t, map[string][]byte{"nested/inner.zip": innerZip})
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	var ran int
	countTask := countingTask(&ran)

	poisoned := []Task{countTask, NewArchiveCatalogerTask(cfg, []Task{countTask}, nil)}
	require.NotNil(t, poisoned[1])

	tsk := newTestTask(t, cfg, poisoned...)
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(newTestSBOM())))

	assert.Equal(t, 2, ran, "two archives, one sub-pipeline task each")

	t.Run("a sub-pipeline of nothing but itself yields no task", func(t *testing.T) {
		only := []Task{NewArchiveCatalogerTask(cfg, []Task{countTask}, nil)}
		assert.Nil(t, NewArchiveCatalogerTask(cfg, only, nil))
	})
}

func Test_archiveCataloger_chainStartsAtTheArchivesOwnFileSystemID(t *testing.T) {
	// extracted files keep the layer digest as their FileSystemID at every level; the nesting chain
	// rides on the traversal's VirtualPath and the coordinate's ArchivePath
	innerZip := makeZip(t, map[string][]byte{"leaf.txt": []byte("leaf")})
	outerZip := makeZip(t, map[string][]byte{"nested/inner.zip": innerZip})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	const layerDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	var chains, fsids []string
	captureTask := NewTask("capture-fsid", func(ctx context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		trav := archive.TraversalFromContext(ctx)
		require.NotNil(t, trav)
		chains = append(chains, archive.VirtualPath(trav.Location))
		fsids = append(fsids, trav.Location.FileSystemID)
		return nil
	})

	tsk := newTestTask(t, cataloging.DefaultArchiveSearchConfig().WithMaxDepth(2), captureTask)
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir, fsid: layerDigest}, sbomsync.NewBuilder(newTestSBOM())))

	assert.Equal(t, []string{layerDigest, layerDigest}, fsids)
	assert.ElementsMatch(t, []string{"/outer.zip", "/outer.zip:nested/inner.zip"}, chains)
}

// twoLayerResolver reports the same archive path under two filesystem ids with different content, as an
// all-layers image scan does for an archive rewritten in a later layer.
type twoLayerResolver struct {
	file.Resolver
	path      string
	contentBy map[string][]byte
}

func Test_archiveCataloger_sameArchivePathInTwoLayersDoesNotCollide(t *testing.T) {
	resolver := twoLayerResolver{
		path: "/app/bundle.zip",
		contentBy: map[string][]byte{
			"layer-one": makeZip(t, map[string][]byte{"lib/config.json": []byte(`{"v":1}`)}),
			"layer-two": makeZip(t, map[string][]byte{"lib/config.json": []byte(`{"v":2}`)}),
		},
	}

	var chains []string
	fileTask := NewTask("record-files", func(ctx context.Context, r file.Resolver, builder sbomsync.Builder) error {
		trav := archive.TraversalFromContext(ctx)
		require.NotNil(t, trav)
		chains = append(chains, trav.Location.FileSystemID)

		locs, err := r.FilesByGlob("**")
		require.NoError(t, err)
		metadata := map[file.Coordinates]file.Metadata{}
		for _, loc := range locs {
			metadata[loc.Coordinates] = file.Metadata{Path: loc.RealPath}
		}
		builder.(sbomsync.Accessor).WriteToSBOM(func(s *sbom.SBOM) {
			s.Artifacts.FileMetadata = metadata
		})
		return nil
	})

	tsk := newTestTask(t, cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1), fileTask)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{
		Packages:     pkg.NewCollection(),
		FileMetadata: map[file.Coordinates]file.Metadata{},
	}}
	require.NoError(t, tsk.Execute(context.Background(), resolver, sbomsync.NewBuilder(s)))

	assert.ElementsMatch(t, []string{"layer-one", "layer-two"}, chains)
	// the tables are keyed by Coordinates, so a collision is a silently missing entry
	assert.Len(t, s.Artifacts.FileMetadata, 2)
}

func Test_archiveCataloger_subPipelineFailureIsRecordedAsAnUnknown(t *testing.T) {
	// runSubPipeline bypasses RunTask, where the coordinate-error to unknown conversion lives
	outerZip := makeZip(t, map[string][]byte{"lib/broken.json": []byte("{")})
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	cfg := cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1)

	t.Run("a coordinate error keeps the coordinates the cataloger named", func(t *testing.T) {
		failing := NewTask("failing-cataloger", func(_ context.Context, r file.Resolver, _ sbomsync.Builder) error {
			locs, err := r.FilesByGlob("**")
			require.NoError(t, err)
			require.NotEmpty(t, locs)
			var errs error
			for _, loc := range locs {
				errs = unknown.Append(errs, loc, errors.New("unable to parse"))
			}
			return errs
		})

		tsk := newTestTask(t, cfg, failing)
		s := newTestSBOM()
		require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)),
			"a cataloger failing inside an archive must not fail the archive or the scan")

		require.Len(t, s.Artifacts.Unknowns, 1)
		for coords, reasons := range s.Artifacts.Unknowns {
			assert.Equal(t, "lib/broken.json", coords.RealPath, "the inner coordinates must survive the merge")
			assert.Equal(t, "/outer.zip", coords.ArchivePath, "and must be addressable per archive")
			assert.Equal(t, []string{"failing-cataloger: unable to parse"}, reasons)
		}
	})

	t.Run("an error with no coordinates is attributed to the archive", func(t *testing.T) {
		failing := NewTask("bare-error-cataloger", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
			return errors.New("cataloger blew up")
		})

		tsk := newTestTask(t, cfg, failing)
		s := newTestSBOM()
		require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)))

		require.Len(t, s.Artifacts.Unknowns, 1)
		reasons, ok := s.Artifacts.Unknowns[file.Coordinates{RealPath: "/outer.zip"}]
		require.True(t, ok, "an error with no location of its own belongs to the containing archive")
		assert.Equal(t, []string{"bare-error-cataloger: cataloger blew up"}, reasons)
	})

	t.Run("a panicking cataloger is recovered and recorded", func(t *testing.T) {
		panicking := NewTask("panicking-cataloger", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
			panic("nope")
		})

		tsk := newTestTask(t, cfg, panicking)
		s := newTestSBOM()
		require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)),
			"a panic inside an archive must not fail the scan")

		reasons, ok := s.Artifacts.Unknowns[file.Coordinates{RealPath: "/outer.zip"}]
		require.True(t, ok)
		require.Len(t, reasons, 1)
		assert.Contains(t, reasons[0], "panicking-cataloger: nope")
	})
}

func Test_archiveCataloger_subPipelineUnknownsAreAddedNotReplaced(t *testing.T) {
	outerZip := makeZip(t, map[string][]byte{"lib/thing.json": []byte("{}")})
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	preexisting := file.Coordinates{RealPath: "lib/thing.json", ArchivePath: "/outer.zip"}
	writer := NewTask("scratch-writer", func(_ context.Context, _ file.Resolver, builder sbomsync.Builder) error {
		builder.(sbomsync.Accessor).WriteToSBOM(func(s *sbom.SBOM) {
			if s.Artifacts.Unknowns == nil {
				s.Artifacts.Unknowns = map[file.Coordinates][]string{}
			}
			s.Artifacts.Unknowns[preexisting] = append(s.Artifacts.Unknowns[preexisting], "recorded by the cataloger itself")
		})
		return nil
	})
	failing := NewTask("failing-cataloger", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		return errors.New("boom")
	})

	tsk := newTestTask(t, cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1), writer, failing)
	s := newTestSBOM()
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)))

	assert.Equal(t, []string{"recorded by the cataloger itself"}, s.Artifacts.Unknowns[preexisting])
	assert.Equal(t, []string{"failing-cataloger: boom"}, s.Artifacts.Unknowns[file.Coordinates{RealPath: "/outer.zip"}])
}

func Test_archiveCataloger_manySmallArchivesAreEachCataloged(t *testing.T) {
	// every archive is released before the next begins, so a scan whose archives sum well past a limit
	// never holds more than one at a time
	entry := bytes.Repeat([]byte("z"), 400)
	entries := map[string][]byte{}
	for i := range 5 {
		entries[fmt.Sprintf("e%d.bin", i)] = entry
	}

	rootDir := t.TempDir()
	names := []string{"one.zip", "two.zip", "three.zip", "four.zip", "five.zip"}
	for _, name := range names {
		require.NoError(t, os.WriteFile(filepath.Join(rootDir, name), makeZip(t, entries), 0o600))
	}

	// room for one archive's entries and their index cost, not for two
	limits := archive.Limits{MaxMemoryBytes: 0, MaxDiskBytes: 20000}

	var seen []string
	fileCounts := map[string]int{}
	tsk := newLimitedTestTask(t, 1, limits, capturingTask(t, &seen, &fileCounts))

	s := newTestSBOM()
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)))

	assert.Len(t, seen, len(names), "every archive must be cataloged: no two were ever held at once")
	for _, archivePath := range seen {
		assert.Equal(t, 5, fileCounts[archivePath], "%s must extract in full", archivePath)
	}
	assert.Empty(t, s.Artifacts.Unknowns)
}

func Test_archiveCataloger_limitsFallWhenAnArchiveIsReleased(t *testing.T) {
	entry := bytes.Repeat([]byte("z"), 400)
	entries := map[string][]byte{}
	for i := range 5 {
		entries[fmt.Sprintf("e%d.bin", i)] = entry
	}

	rootDir := t.TempDir()
	for _, name := range []string{"one.zip", "two.zip"} {
		require.NoError(t, os.WriteFile(filepath.Join(rootDir, name), makeZip(t, entries), 0o600))
	}

	// room in memory for one archive's entries and their index cost, not for two at once
	limiter := archive.NewLimiter(archive.Limits{MaxMemoryBytes: 20000, MaxDiskBytes: 0})

	// sampled while the archive is still held
	var extracted []int
	var peakMemory int64
	sample := NewTask("sample", func(_ context.Context, r file.Resolver, _ sbomsync.Builder) error {
		locs, err := r.FilesByGlob("**")
		require.NoError(t, err)
		extracted = append(extracted, len(locs))
		if mem, _ := limiter.InUse(); mem > peakMemory {
			peakMemory = mem
		}
		return nil
	})

	c := newTestCataloger(1, limiter, sample)
	require.NoError(t, c.catalog(context.Background(), dirTestResolver{dir: rootDir}, 0, sbomsync.NewBuilder(newTestSBOM())))

	assert.Equal(t, []int{5, 5}, extracted,
		"both archives must extract in full: the first is released before the second is admitted")
	assert.Positive(t, peakMemory, "entries within the memory limit are held in memory")

	mem, disk := limiter.InUse()
	assert.Zero(t, mem, "the memory limit must fall back to nothing once the walk unwinds")
	assert.Zero(t, disk, "and so must the disk limit")
}

func newTestCataloger(maxDepth int, limiter *archive.Limiter, subPipeline ...Task) *archiveCataloger {
	return &archiveCataloger{
		maxDepth:    maxDepth,
		subPipeline: subPipeline,
		limiter:     limiter,
		progress:    bus.StartCatalogerTask(context.Background(), archiveCatalogerProgressInfo(), -1, ""),
	}
}

func Test_archiveCataloger_archiveWhoseOwnBytesExceedTheDiskLimitIsSkipped(t *testing.T) {
	// a streamed archive's own bytes must be placed before it can be opened; when they do not fit on
	// disk the archive is skipped rather than waited for, and a sibling that fits is cataloged in full
	oversized := makeZip(t, map[string][]byte{"payload.bin": incompressible(8000)})
	small := makeZip(t, map[string][]byte{"ok.txt": []byte("ok")})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "oversized.zip"), oversized, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "small.zip"), small, 0o600))

	// room for the small archive's bytes, its one entry and that entry's index cost
	diskLimit := int64(len(small)) + 3000
	require.Greater(t, int64(len(oversized)), diskLimit, "the fixture must actually exceed the limit")

	limits := archive.Limits{MaxMemoryBytes: 0, MaxDiskBytes: diskLimit}

	var seen []string
	fileCounts := map[string]int{}
	tsk := newLimitedTestTask(t, 1, limits, capturingTask(t, &seen, &fileCounts))

	s := newTestSBOM()
	require.NoError(t, tsk.Execute(context.Background(), streamingDirResolver{dirTestResolver{dir: rootDir}}, sbomsync.NewBuilder(s)),
		"reaching a limit must not fail the scan")

	assert.Equal(t, []string{"/small.zip"}, seen, "the oversized archive is skipped and the sibling is still cataloged")
	assert.Equal(t, 1, fileCounts["/small.zip"])

	reasons := s.Artifacts.Unknowns[file.Coordinates{RealPath: "/oversized.zip"}]
	require.Len(t, reasons, 1, "the skip must be recorded against the archive; got %v", s.Artifacts.Unknowns)
	assert.Contains(t, reasons[0], "archive skipped")
}

func Test_archiveCataloger_zeroDiskLimitTruncatesWhatWillNotFitInMemory(t *testing.T) {
	// with a zero disk limit there is nowhere to overflow, so an archive's entries are stored exactly
	// while they fit in memory
	oversized := makeZip(t, map[string][]byte{"payload.bin": incompressible(8000)})
	small := makeZip(t, map[string][]byte{"ok.txt": []byte("ok")})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "oversized.zip"), oversized, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "small.zip"), small, 0o600))

	// room for the small archive's entry and its index cost, not for the oversized one's
	limits := archive.Limits{MaxMemoryBytes: 3000, MaxDiskBytes: 0}

	var seen []string
	fileCounts := map[string]int{}
	tsk := newLimitedTestTask(t, 1, limits, capturingTask(t, &seen, &fileCounts))

	s := newTestSBOM()
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)),
		"reaching the disk limit must not fail the scan")

	assert.ElementsMatch(t, []string{"/oversized.zip", "/small.zip"}, seen)
	assert.Equal(t, 1, fileCounts["/small.zip"], "the archive that fits in memory needs no disk at all")
	assert.Equal(t, 0, fileCounts["/oversized.zip"], "the entry that does not fit is refused")

	assert.Contains(t, s.Artifacts.Unknowns, file.Coordinates{RealPath: "/oversized.zip"})
	assert.NotContains(t, s.Artifacts.Unknowns, file.Coordinates{RealPath: "/small.zip"})
}

func Test_archiveCataloger_nestedArchiveExceedingALimitIsTruncatedNotBlocked(t *testing.T) {
	// the walk descends before it unwinds, so nothing is released while a child waits; a child that does
	// not fit is truncated and the scan finishes
	inner := makeZip(t, map[string][]byte{"payload.bin": incompressible(3000)})
	outer := makeZip(t, map[string][]byte{"inner.zip": inner})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outer, 0o600))

	// enough for the outer archive's one entry and its index cost, plus the inner's index cost, and not
	// the inner's payload on top
	diskLimit := int64(len(inner)) + 2*2100 + 500
	require.Greater(t, 3000, 500, "the inner payload must not fit in the slack")

	limits := archive.Limits{MaxMemoryBytes: 0, MaxDiskBytes: diskLimit}

	var seen []string
	fileCounts := map[string]int{}
	tsk := newLimitedTestTask(t, 2, limits, capturingTask(t, &seen, &fileCounts))

	s := newTestSBOM()
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)))

	assert.Equal(t, []string{"/outer.zip", "/outer.zip:inner.zip"}, seen)
	assert.Equal(t, 1, fileCounts["/outer.zip"], "the parent is cataloged in full")
	assert.Equal(t, 0, fileCounts["/outer.zip:inner.zip"], "the child it cannot afford is truncated")
	assert.Contains(t, s.Artifacts.Unknowns, file.Coordinates{RealPath: "inner.zip", ArchivePath: "/outer.zip"})
}

// allFilesResolver is dirTestResolver without a filesystem id.
type allFilesResolver struct {
	file.Resolver
	dir string
}

func Test_archiveCataloger_discoverArchivesSelectsTarFamily(t *testing.T) {
	marker := map[string][]byte{"nested/marker.txt": []byte("hello")}

	scanDir := t.TempDir()
	for name, body := range map[string][]byte{
		"bundle.tar.gz": makeTarGz(t, marker),
		"bundle.tgz":    makeTarGz(t, marker),
		"bundle.tar":    makeTar(t, marker),
		"bundle.zip":    makeZip(t, marker),
		"notes.txt":     []byte("not an archive at all"),
	} {
		require.NoError(t, os.WriteFile(filepath.Join(scanDir, name), body, 0o600))
	}

	var seen []string
	fileCounts := map[string]int{}
	tsk := newTestTask(t, cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1), capturingTask(t, &seen, &fileCounts))
	require.NoError(t, tsk.Execute(context.Background(), allFilesResolver{dir: scanDir}, sbomsync.NewBuilder(newTestSBOM())))

	assert.ElementsMatch(t, []string{"/bundle.tar.gz", "/bundle.tgz", "/bundle.tar", "/bundle.zip"}, seen,
		"every tar-family archive must be reached, and the plain text file must not be")
	for _, archivePath := range seen {
		assert.Equal(t, 1, fileCounts[archivePath], "%s must have been extracted", archivePath)
	}

	t.Run("the MIME types the tar family is sniffed as are in the set discovery asks for", func(t *testing.T) {
		for _, mt := range []string{"application/x-tar", "application/gzip", "application/x-gtar", "application/zip"} {
			assert.True(t, mimetype.ArchiveMIMETypeSet.Has(mt), "%s must be a candidate archive type", mt)
		}
	})
}

type recordingPublisher struct {
	events []partybus.Event
}

func Test_archiveCatalogerTask_publishesOneProgressRowPerCataloger(t *testing.T) {
	// a consumer keying rows by ID (as the syft CLI does) replaces a republished row and never sees it
	// complete, so each cataloger keeps to the one row it already owns
	inner := makeZip(t, map[string][]byte{"inner/file.txt": []byte("hello")})
	scanDir := t.TempDir()
	for _, name := range []string{"one.zip", "two.zip"} {
		require.NoError(t, os.WriteFile(filepath.Join(scanDir, name), inner, 0o600))
	}

	publisher := &recordingPublisher{}
	bus.Set(publisher)
	t.Cleanup(func() { bus.Set(nil) })

	// the archive row's stage as each archive's sub-pipeline starts: the previous archive is done by then,
	// so the row must read the walk's own count rather than anything a nested cataloger left behind
	var rows []*monitor.TaskProgress
	var stageAtEntry []string
	noisy := NewTask("noisy", func(ctx context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		stageAtEntry = append(stageAtEntry, publisher.events[0].Value.(progress.StagedProgressable).Stage())
		p := bus.StartCatalogerTask(ctx, monitor.GenericTask{ID: "noisy"}, 3, "")
		rows = append(rows, p)
		p.AtomicStage.Set("working on something")
		p.Add(3)
		p.SetCompleted()
		return nil
	})

	tsk := newTestTask(t, cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1), noisy)
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: scanDir}, sbomsync.NewBuilder(newTestSBOM())))

	var started []string
	for _, e := range publisher.events {
		if e.Type != event.CatalogerTaskStarted {
			continue
		}
		info, ok := e.Source.(monitor.GenericTask)
		require.True(t, ok, "expected a generic task as the event source")
		started = append(started, info.ID)
	}

	assert.Equal(t, []string{ArchiveCatalogerTaskName, "noisy"}, started,
		"each cataloger publishes one row, however many archives the walk enters")

	require.Len(t, rows, 2, "the sub-pipeline ran once per archive")
	assert.Same(t, rows[0], rows[1], "both runs must report into the one row that cataloger owns")
	assert.Equal(t, int64(6), rows[0].Current(), "what every run found is counted onto that row")

	require.Len(t, publisher.events, 2)
	prog, ok := publisher.events[0].Value.(progress.StagedProgressable)
	require.True(t, ok)
	assert.ErrorIs(t, prog.Error(), progress.ErrCompleted, "the row must be completed, or a waiting consumer never finishes")
	assert.Equal(t, int64(2), prog.Current(), "the archive row counts every archive the walk entered")
	assert.Equal(t, "2 archives", prog.Stage(), "and says so once the walk is done")

	// one.zip sorts before two.zip, and the resolver walks the scan directory in lexical order
	assert.Equal(t, []string{"", "1 archives (/one.zip)"}, stageAtEntry,
		"the row must take its stage back from the sub-pipeline once an archive is done")
}

func Test_archiveCataloger_reportsPeakUsageAndTheSlowestArchive(t *testing.T) {
	// self time excludes nested archives, or the outer archive would be named every scan
	innerJar := makeZip(t, map[string][]byte{"README.txt": []byte("inner")})
	outerZip := makeZip(t, map[string][]byte{"lib/inner.jar": innerJar})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	const innerWork = 40 * time.Millisecond
	slow := NewTask("slow-inside-the-inner-archive", func(ctx context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		if trav := archive.TraversalFromContext(ctx); trav != nil && strings.HasSuffix(archive.VirtualPath(trav.Location), "inner.jar") {
			time.Sleep(innerWork)
		}
		return nil
	})

	limiter := archive.NewLimiter(archive.Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1})
	c := newTestCataloger(3, limiter, slow)
	require.NoError(t, c.catalog(context.Background(), dirTestResolver{dir: rootDir}, 0, sbomsync.NewBuilder(newTestSBOM())))

	assert.Equal(t, "/outer.zip:lib/inner.jar", c.slowestPath, "the slowest archive is named by its full chain")
	assert.GreaterOrEqual(t, c.slowest, innerWork)
	assert.Equal(t, int64(2), c.progress.Current())

	// the peaks outlive the walk that set them
	peakMemory, _ := limiter.Peak()
	assert.Positive(t, peakMemory, "entries held in memory must show on the peak")
	memory, disk := limiter.InUse()
	assert.Zero(t, memory)
	assert.Zero(t, disk)
}

func Test_archiveCataloger_slowestIsUnsetWhenNoArchiveIsCataloged(t *testing.T) {
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "notes.txt"), []byte("not an archive"), 0o600))

	noop := NewTask("noop", func(context.Context, file.Resolver, sbomsync.Builder) error { return nil })
	c := newTestCataloger(2, archive.NewLimiter(archive.Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1}), noop)
	require.NoError(t, c.catalog(context.Background(), dirTestResolver{dir: rootDir}, 0, sbomsync.NewBuilder(newTestSBOM())))

	assert.Empty(t, c.slowestPath)
	assert.Zero(t, c.progress.Current())
	c.logStats() // must not panic with nothing to report
}

func Test_archiveCataloger_aMisnamedNonArchiveIsNotAnError(t *testing.T) {
	// the name says archive, the content does not: it is never opened
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "notes.zip"),
		[]byte("this is prose, not an archive, whatever the extension claims\n"), 0o600))

	var ran int
	tsk := newTestTask(t, cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1), countingTask(&ran))

	err := tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(newTestSBOM()))

	assert.NoError(t, err, "a file that is not an archive is not a failure to report")
	assert.Zero(t, ran, "and nothing is cataloged inside it")
}

func Test_archiveCataloger_catalogsAZipBehindALauncherScript(t *testing.T) {
	// the Spring Boot executable jar shape: content sniffing types it as a shell script, so it reaches
	// the walk only by name and qualifies only by its end-of-central-directory record
	inner := makeZip(t, map[string][]byte{"nested/marker.txt": []byte("found me")})
	prefixed := append([]byte("#!/bin/bash\nexec java -jar \"$0\" \"$@\"\nexit 0\n"),
		makeZip(t, map[string][]byte{"BOOT-INF/lib/inner.jar": inner})...)

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "app.jar"), prefixed, 0o600))

	var seen []string
	tsk := newTestTask(t, cataloging.DefaultArchiveSearchConfig().WithMaxDepth(3), capturingTask(t, &seen, nil))
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(newTestSBOM())))

	assert.Equal(t, []string{"/app.jar", "/app.jar:BOOT-INF/lib/inner.jar"}, seen,
		"the stub must not hide the archive, and the walk must carry on into what it holds")
}

func (d dirTestResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	return filesByMIMEType(d.dir, d.fsid, types...)
}

func filesByMIMEType(dir, fsid string, types ...string) ([]file.Location, error) {
	wanted := strset.New(types...)
	var locs []file.Location
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		mimeType := stereoscopeFile.MIMEType(f)
		if closeErr := f.Close(); closeErr != nil {
			return closeErr
		}
		if !wanted.Has(mimeType) {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		coords := file.Coordinates{RealPath: "/" + filepath.ToSlash(rel), FileSystemID: fsid}
		locs = append(locs, file.NewLocationFromCoordinates(coords))
		return nil
	})
	return locs, err
}

func (d dirTestResolver) FileContentsByLocation(loc file.Location) (io.ReadCloser, error) {
	return os.Open(filepath.Join(d.dir, filepath.FromSlash(loc.RealPath)))
}

// makeZip builds a zip in sorted entry-name order: limits are enforced as the walk proceeds, so entry
// order decides which entries land before a truncation.
func makeZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range names {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write(entries[name])
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// matchesAnyGlob matches the resolver-relative path with a leading slash, the form a real resolver
// globs over. No patterns matches everything.
func matchesAnyGlob(root, path string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	rel = "/" + filepath.ToSlash(rel)
	for _, pattern := range patterns {
		if ok, err := doublestar.Match(pattern, rel); err == nil && ok {
			return true
		}
	}
	return false
}

func (a allFilesResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	return dirTestResolver{dir: a.dir}.FilesByGlob(patterns...)
}

func (r twoLayerResolver) FilesByGlob(_ ...string) ([]file.Location, error) {
	return nil, nil
}

func (d dirTestResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var locs []file.Location
	err := filepath.WalkDir(d.dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if !matchesAnyGlob(d.dir, path, patterns) {
			return nil
		}
		rel, err := filepath.Rel(d.dir, path)
		if err != nil {
			return err
		}
		coords := file.Coordinates{RealPath: "/" + filepath.ToSlash(rel), FileSystemID: d.fsid}
		locs = append(locs, file.NewLocationFromCoordinates(coords))
		return nil
	})
	return locs, err
}

func (r twoLayerResolver) FilesByMIMEType(_ ...string) ([]file.Location, error) {
	var locs []file.Location
	for _, fsid := range []string{"layer-one", "layer-two"} {
		locs = append(locs, file.NewLocationFromCoordinates(file.Coordinates{RealPath: r.path, FileSystemID: fsid}))
	}
	return locs, nil
}

func (r twoLayerResolver) FileContentsByLocation(loc file.Location) (io.ReadCloser, error) {
	body, ok := r.contentBy[loc.FileSystemID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

// incompressible returns n bytes deflate cannot shrink, so an archive built from them has a
// predictable size to set a limit against.
func incompressible(n int) []byte {
	b := make([]byte, n)
	x := uint32(12345)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	return b
}

func makeTarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	require.NoError(t, writeTar(t, gw, entries))
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

func makeTar(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, writeTar(t, &buf, entries))
	return buf.Bytes()
}

func writeTar(t *testing.T, w io.Writer, entries map[string][]byte) error {
	t.Helper()
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	tw := tar.NewWriter(w)
	for _, name := range names {
		body := entries[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			return err
		}
		if _, err := tw.Write(body); err != nil {
			return err
		}
	}
	return tw.Close()
}

func (a allFilesResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	return filesByMIMEType(a.dir, "", types...)
}

func (a allFilesResolver) FileContentsByLocation(loc file.Location) (io.ReadCloser, error) {
	return os.Open(filepath.Join(a.dir, filepath.FromSlash(loc.RealPath)))
}

func (p *recordingPublisher) Publish(e partybus.Event) {
	p.events = append(p.events, e)
}

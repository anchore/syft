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
	"path"
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

// dirTestResolver is a minimal file.Resolver over a directory for exercising the archive cataloger
// task: FilesByMIMEType reports any zip-family file (ignoring the actual MIME type arguments) and
// FileContentsByLocation reads from disk. All other resolver methods are unimplemented.
type dirTestResolver struct {
	file.Resolver
	dir  string
	fsid string
}

func (d dirTestResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	return filesByMIMEType(d.dir, d.fsid, types...)
}

// filesByMIMEType is what a real resolver does: sniff each file's content at index time and return
// the ones whose type was asked for. The test resolvers used to ignore the argument and return
// everything, which made every caller look like it was being handed archives - and hid the fact
// that the task now asks two different questions with two different consequences.
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

// tarTestResolver is a minimal file.Resolver over one archive's overflow tar, standing in for the real
// tar-backed resolver: the archive cataloger's own tests should not need the syft-subtree
// fileresolver package, but they do need something shaped like what it produces.
//
// FilesByMIMEType reports any zip-family entry (ignoring the MIME arguments) and
// FileContentsByLocation opens that entry at its offset in the tar. The reader it returns carries the
// marker the extraction path looks for, so a nested archive is exercised through the read-in-place
// route it takes in a real scan rather than through a copy.
type tarTestResolver struct {
	file.Resolver
	entries     map[string]stereoscopeFile.TarIndexEntry
	fsid        string
	archivePath string
}

// newTarTestResolver is an archive.ResolverFactory over the overflow tar.
func newTarTestResolver(overflow archive.Overflow) (file.Resolver, archive.IndexResult, error) {
	r := &tarTestResolver{entries: map[string]stereoscopeFile.TarIndexEntry{}, fsid: overflow.FileSystemID, archivePath: overflow.ArchivePath}
	if _, err := stereoscopeFile.NewTarIndex(overflow.TarPath, func(entry stereoscopeFile.TarIndexEntry) error {
		name := entry.ToTarFileEntry().Header.Name
		r.entries[path.Clean("/"+name)] = entry
		return nil
	}); err != nil {
		return nil, archive.IndexResult{}, err
	}
	return r, archive.IndexResult{Records: len(r.entries)}, nil
}

func (r *tarTestResolver) sortedNames() []string {
	names := make([]string, 0, len(r.entries))
	for name := range r.entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (r *tarTestResolver) location(name string) file.Location {
	return file.NewLocationFromCoordinates(file.Coordinates{RealPath: name, FileSystemID: r.fsid, ArchivePath: r.archivePath})
}

func (r *tarTestResolver) FilesByMIMEType(_ ...string) ([]file.Location, error) {
	var locs []file.Location
	for _, name := range r.sortedNames() {
		switch strings.ToLower(filepath.Ext(name)) {
		case ".zip", ".jar", ".war":
			locs = append(locs, r.location(name))
		}
	}
	return locs, nil
}

func (r *tarTestResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var locs []file.Location
	for _, name := range r.sortedNames() {
		for _, pattern := range patterns {
			if matched, err := doublestar.Match(pattern, strings.TrimPrefix(name, "/")); err == nil && matched {
				locs = append(locs, r.location(name))
				break
			}
		}
	}
	return locs, nil
}

func (r *tarTestResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var locs []file.Location
	for _, p := range paths {
		name := path.Clean("/" + p)
		if _, ok := r.entries[name]; ok {
			locs = append(locs, r.location(name))
		}
	}
	return locs, nil
}

func (r *tarTestResolver) FileContentsByLocation(loc file.Location) (io.ReadCloser, error) {
	entry, ok := r.entries[loc.RealPath]
	if !ok {
		return nil, fmt.Errorf("no entry %q", loc.RealPath)
	}
	contents := entry.Open()
	seekable, ok := contents.(randomAccessReadCloser)
	if !ok {
		return contents, nil
	}
	return testOverflowEntry{seekable}, nil
}

type randomAccessReadCloser interface {
	io.ReadCloser
	io.ReaderAt
	io.Seeker
}

// testOverflowEntry carries the marker method that says "already random access on a file this scan
// wrote", which is how a nested archive gets read where it lies.
type testOverflowEntry struct {
	randomAccessReadCloser
}

func (testOverflowEntry) OverflowArchiveEntry() {}

// makeZip builds a zip in sorted entry-name order. The order matters and must not be the map's:
// extraction limits are enforced as the walk proceeds, so which entries land before a truncation is
// a function of entry order, and a randomized order makes any limit assertion flaky.
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

// matchesAnyGlob reports whether the path matches one of the patterns, against the resolver-relative
// path with a leading slash, which is the form a real resolver globs over. No patterns means
// everything matches.
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

// FilesByGlob for the resolvers that only ever stand in for a MIME lookup: the archive walk asks
// them for archive-named files too, and an unimplemented method on an embedded nil resolver panics.
func (a allFilesResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	return dirTestResolver{dir: a.dir}.FilesByGlob(patterns...)
}

func (r twoLayerResolver) FilesByGlob(_ ...string) ([]file.Location, error) {
	return nil, nil
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

	var captured []*archive.Traversal
	captureTask := NewTask("capture-traversal", func(ctx context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		captured = append(captured, archive.TraversalFromContext(ctx))
		return nil
	})

	cfg := cataloging.DefaultArchiveSearchConfig().WithMaxDepth(3)

	newResolver := newTarTestResolver

	tsk := NewArchiveCatalogerTask(cfg, []Task{captureTask}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	err := tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s))
	require.NoError(t, err)

	var chains []string
	for _, trav := range captured {
		require.NotNil(t, trav)
		chains = append(chains, trav.VirtualPath)
	}
	// java archives are traversed like any other archive when the task is enabled
	assert.ElementsMatch(t, []string{
		"/outer.zip",
		"/outer.zip:lib/inner.jar",
		"/outer.zip:nested/inner.zip",
	}, chains)

	// verify parent linkage and depth
	for _, trav := range captured {
		if trav.Depth == 1 {
			assert.Nil(t, trav.Parent)
			continue
		}
		require.NotNil(t, trav.Parent)
		assert.Equal(t, trav.Parent.Depth+1, trav.Depth)
		assert.True(t, strings.HasPrefix(trav.VirtualPath, trav.Parent.VirtualPath+":"))
	}
}

func Test_archiveCataloger_truncationStillCatalogs(t *testing.T) {
	// a limit is a truncation, not a failure: the sub-pipeline must still run over whatever was
	// written, so packages found before the limit survive. Discarding the whole archive was the
	// original behavior and it silently lost every package in an oversized archive.
	big := bytes.Repeat([]byte("x"), 4096)
	outerZip := makeZip(t, map[string][]byte{
		"a/small.txt": []byte("small"),
		"b/big.txt":   big,
	})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	var ran int
	countTask := NewTask("count-runs", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		ran++
		return nil
	})

	// small.txt costs a header block and a padded data block; big.txt's header does not fit after
	// them. The archive's own bytes are held in memory at the default limit, so what is charged to
	// disk here is only the tar its entries are written into.
	cfg := cataloging.DefaultArchiveSearchConfig().
		WithMaxDepth(1).
		WithMaxDiskBytes(1500)

	newResolver := newTarTestResolver

	tsk := NewArchiveCatalogerTask(cfg, []Task{countTask}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	err := tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s))

	require.NoError(t, err, "a truncated extraction must not fail the scan")
	assert.Equal(t, 1, ran, "the sub-pipeline must run over the partial contents")

	// and the SBOM says the archive was read in part, at the archive's own coordinates: a scan that
	// finished cleanly but saw only some of an archive is not the same SBOM as one that saw all of
	// it, and a debug log does not survive the run that wrote it
	reasons, ok := s.Artifacts.Unknowns[file.Coordinates{RealPath: "/outer.zip"}]
	require.True(t, ok, "the truncation must be recorded against the archive; got %v", s.Artifacts.Unknowns)
	require.Len(t, reasons, 1)
	assert.Contains(t, reasons[0], "archive cataloged from part of its contents")
	assert.Contains(t, reasons[0], ArchiveCatalogerTaskName, "the unknown names the task that recorded it")
}

func Test_archiveCataloger_failureIsRecordedAndSkipsSubPipeline(t *testing.T) {
	// a genuine failure is not a truncation: nothing usable was produced, so the sub-pipeline must
	// not run over an empty tree, and the failure must be visible in the SBOM rather than only in
	// the logs
	rootDir := t.TempDir()
	// a zip whose entry data has been overwritten: its header still says zip and its
	// end-of-central-directory record is intact, so it is detected as an archive and then fails when
	// the entry is read. Prose named `.zip` would not do - that is not detected as an archive at all,
	// which is a different requirement and is covered by
	// Test_archiveCataloger_aMisnamedNonArchiveIsNotAnError.
	corrupt := makeZip(t, map[string][]byte{"data.bin": incompressible(4096)})
	require.Greater(t, len(corrupt), 1024)
	for i := 100; i < 600; i++ {
		corrupt[i] ^= 0xff
	}
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "corrupt.zip"), corrupt, 0o600))

	// a second, healthy archive proves the failure does not stop the walk
	goodZip := makeZip(t, map[string][]byte{"ok.txt": []byte("ok")})
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "good.zip"), goodZip, 0o600))

	var ran int
	countTask := NewTask("count-runs", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		ran++
		return nil
	})

	cfg := cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1)
	newResolver := newTarTestResolver

	tsk := NewArchiveCatalogerTask(cfg, []Task{countTask}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	err := tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s))

	// the failure must be a CoordinateError, because that is what executor.go's
	// unknown.ExtractCoordinateErrors pulls out and records in sbom.Artifacts.Unknowns. A plain
	// error would propagate as a scan failure instead of being reported against the archive
	require.Error(t, err)
	coordErrs, remaining := unknown.ExtractCoordinateErrors(err)
	assert.NoError(t, remaining, "nothing may escape as a non-coordinate error")
	require.Len(t, coordErrs, 1)
	assert.Equal(t, "/corrupt.zip", coordErrs[0].Coordinates.RealPath)

	// and the healthy archive was still cataloged: one bad archive must not stop the walk
	assert.Equal(t, 1, ran, "the sub-pipeline must still run for the archive that extracted cleanly")
}

func Test_NewArchiveCatalogerTask_gating(t *testing.T) {
	newResolver := newTarTestResolver
	someTask := NewTask("noop", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error { return nil })

	tests := []struct {
		name        string
		cfg         cataloging.ArchiveSearchConfig
		subPipeline []Task
		resolver    archive.ResolverFactory
		wantTask    bool
	}{
		{
			name:        "disabled at depth 0",
			cfg:         cataloging.DefaultArchiveSearchConfig(),
			subPipeline: []Task{someTask},
			resolver:    newResolver,
		},
		{
			name:        "no sub-pipeline",
			cfg:         cataloging.DefaultArchiveSearchConfig().WithMaxDepth(2),
			subPipeline: nil,
			resolver:    newResolver,
		},
		{
			name:        "no resolver factory",
			cfg:         cataloging.DefaultArchiveSearchConfig().WithMaxDepth(2),
			subPipeline: []Task{someTask},
			resolver:    nil,
		},
		{
			name:        "enabled",
			cfg:         cataloging.DefaultArchiveSearchConfig().WithMaxDepth(2),
			subPipeline: []Task{someTask},
			resolver:    newResolver,
			wantTask:    true,
		},
		{
			name:        "enabled at negative depth",
			cfg:         cataloging.DefaultArchiveSearchConfig().WithMaxDepth(-1),
			subPipeline: []Task{someTask},
			resolver:    newResolver,
			wantTask:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewArchiveCatalogerTask(tt.cfg, tt.subPipeline, tt.resolver, nil, nil)
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
	// an archive in the scan source is depth 1, so MaxDepth 1 must catalog it and not descend
	innerZip := makeZip(t, map[string][]byte{"deep.txt": []byte("deep")})
	outerZip := makeZip(t, map[string][]byte{"nested/inner.zip": innerZip})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	newResolver := newTarTestResolver

	run := func(t *testing.T, depth int) []string {
		t.Helper()
		var seen []string
		captureTask := NewTask("capture", func(ctx context.Context, _ file.Resolver, _ sbomsync.Builder) error {
			trav := archive.TraversalFromContext(ctx)
			require.NotNil(t, trav)
			seen = append(seen, trav.VirtualPath)
			return nil
		})

		tsk := NewArchiveCatalogerTask(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(depth), []Task{captureTask}, newResolver, nil, nil)
		require.NotNil(t, tsk)

		s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
		require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)),
			"reaching the depth bound must not be an error")
		return seen
	}

	assert.Equal(t, []string{"/outer.zip"}, run(t, 1), "depth 1 catalogs the top-level archive and does not descend")
	assert.ElementsMatch(t, []string{"/outer.zip", "/outer.zip:nested/inner.zip"}, run(t, 2), "depth 2 descends one level")
}

func Test_NewArchiveCatalogerTask_dropsItselfFromSubPipeline(t *testing.T) {
	// the task drives recursion with its own depth-bounded walk, so a copy of itself in the
	// sub-pipeline would process every nesting level twice. The depth bound still terminates the
	// recursion, so the symptom is duplicated packages rather than a hang - which is exactly the
	// kind of failure nobody notices in a large SBOM.
	newResolver := newTarTestResolver
	cfg := cataloging.DefaultArchiveSearchConfig().WithMaxDepth(2)

	innerZip := makeZip(t, map[string][]byte{"leaf.txt": []byte("leaf")})
	outerZip := makeZip(t, map[string][]byte{"nested/inner.zip": innerZip})
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	var ran int
	countTask := NewTask("count-runs", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		ran++
		return nil
	})

	// a sub-pipeline that (incorrectly) carries an archive cataloger task alongside real work
	poisoned := []Task{countTask, NewArchiveCatalogerTask(cfg, []Task{countTask}, newResolver, nil, nil)}
	require.NotNil(t, poisoned[1])

	tsk := NewArchiveCatalogerTask(cfg, poisoned, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)))

	// two archives, one sub-pipeline task each: the nested archive task was dropped, so no level is
	// processed twice
	assert.Equal(t, 2, ran)

	t.Run("a sub-pipeline of nothing but itself yields no task", func(t *testing.T) {
		only := []Task{NewArchiveCatalogerTask(cfg, []Task{countTask}, newResolver, nil, nil)}
		assert.Nil(t, NewArchiveCatalogerTask(cfg, only, newResolver, nil, nil))
	})
}

// FilesByGlob lists the files under the resolver's directory that match, stamped with its
// filesystem id, so a sub-pipeline task can record file artifacts the way a real file cataloger
// does. With no patterns it lists everything, which is what the sub-pipeline tasks here want.
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

func Test_archiveCataloger_chainStartsAtTheArchivesOwnFileSystemID(t *testing.T) {
	// covers syft/archive-content-identity#nested-filesystem-id-chain, scenario "image source chain
	// extends the layer digest": an image-source archive's extracted files keep the layer digest as
	// their FileSystemID (inherited unchanged down the nesting chain), while the archive nesting chain
	// is carried separately as the traversal's VirtualPath / the coordinate ArchivePath
	innerZip := makeZip(t, map[string][]byte{"leaf.txt": []byte("leaf")})
	outerZip := makeZip(t, map[string][]byte{"nested/inner.zip": innerZip})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	const layerDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	var chains []string
	var fsids []string
	captureTask := NewTask("capture-fsid", func(ctx context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		trav := archive.TraversalFromContext(ctx)
		require.NotNil(t, trav)
		chains = append(chains, trav.VirtualPath)
		fsids = append(fsids, trav.FileSystemID)
		return nil
	})

	newResolver := newTarTestResolver

	tsk := NewArchiveCatalogerTask(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(2), []Task{captureTask}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir, fsid: layerDigest}, sbomsync.NewBuilder(s)))

	// the layer digest is preserved unchanged at every level as the filesystem the archive lives on
	assert.Equal(t, []string{layerDigest, layerDigest}, fsids)

	// exact strings: the archive path is serialized into the SBOM, so a changed shape is a changed
	// output format, not an internal detail
	assert.ElementsMatch(t, []string{
		"/outer.zip",
		"/outer.zip:nested/inner.zip",
	}, chains)
}

// twoLayerResolver reports the same archive path twice under two different filesystem ids, each
// holding different content — what an all-layers image scan yields for an archive rewritten in a
// later layer. FilesByMIMEType dedupes on the file reference rather than the path, so both survive.
type twoLayerResolver struct {
	file.Resolver
	path      string
	contentBy map[string][]byte
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

func Test_archiveCataloger_sameArchivePathInTwoLayersDoesNotCollide(t *testing.T) {
	// the collision the chain exists to prevent: two layers holding /app/bundle.zip at the same path
	// composed the same identifier while the chain was seeded from the parent traversal, so the two
	// extractions' contents overwrote each other in the coordinate-keyed file tables
	resolver := twoLayerResolver{
		path: "/app/bundle.zip",
		contentBy: map[string][]byte{
			"layer-one": makeZip(t, map[string][]byte{"lib/config.json": []byte(`{"v":1}`)}),
			"layer-two": makeZip(t, map[string][]byte{"lib/config.json": []byte(`{"v":2}`)}),
		},
	}

	var chains []string
	// record a file artifact per location the way a file cataloger does, so the merge into the shared
	// SBOM exercises the coordinate-keyed tables rather than only the traversal
	fileTask := NewTask("record-files", func(ctx context.Context, r file.Resolver, builder sbomsync.Builder) error {
		trav := archive.TraversalFromContext(ctx)
		require.NotNil(t, trav)
		chains = append(chains, trav.FileSystemID)

		locs, err := r.FilesByGlob("**")
		require.NoError(t, err)
		accessor := builder.(sbomsync.Accessor)
		accessor.WriteToSBOM(func(s *sbom.SBOM) {
			for _, loc := range locs {
				s.Artifacts.FileMetadata[loc.Coordinates] = file.Metadata{Path: loc.RealPath}
			}
		})
		return nil
	})

	newResolver := newTarTestResolver

	tsk := NewArchiveCatalogerTask(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1), []Task{fileTask}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{
		Packages:     pkg.NewCollection(),
		FileMetadata: map[file.Coordinates]file.Metadata{},
	}}
	require.NoError(t, tsk.Execute(context.Background(), resolver, sbomsync.NewBuilder(s)))

	assert.ElementsMatch(t, []string{"layer-one", "layer-two"}, chains,
		"the two archives keep the distinct filesystem ids of the layers they were found in")

	// two file-table entries, asserted as a count: the tables are keyed by Coordinates, so a
	// collision is a silently missing entry rather than any kind of error. The same archive path in
	// two layers stays distinct because the coordinates differ by FileSystemID (the layer), not by
	// ArchivePath (which is identical here)
	assert.Len(t, s.Artifacts.FileMetadata, 2)
}

func Test_archiveCataloger_subPipelineFailureIsRecordedAsAnUnknown(t *testing.T) {
	// syft/nested-archive-cataloging#archive-failure-is-not-fatal wants a catalog failure inside an
	// archive "visible in output rather than only in logs". runSubPipeline bypasses RunTask, which is
	// where the coordinate-error to unknown conversion lives, so the error used to be trace-logged
	// and dropped.
	outerZip := makeZip(t, map[string][]byte{"lib/broken.json": []byte("{")})
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	newResolver := newTarTestResolver
	cfg := cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1)

	t.Run("a coordinate error keeps the coordinates the cataloger named", func(t *testing.T) {
		// the cataloger attributed its failure to a file it was reading, which is the normal case and
		// is more precise than the archive: it must not be flattened onto the archive's coordinates
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

		tsk := NewArchiveCatalogerTask(cfg, []Task{failing}, newResolver, nil, nil)
		require.NotNil(t, tsk)

		s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
		require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)),
			"a cataloger failing inside an archive must not fail the archive or the scan")

		require.Len(t, s.Artifacts.Unknowns, 1)
		for coords, reasons := range s.Artifacts.Unknowns {
			assert.Equal(t, "/lib/broken.json", coords.RealPath, "the inner coordinates must survive the merge")
			assert.Equal(t, "/outer.zip", coords.ArchivePath, "and must be addressable per archive")
			assert.Equal(t, []string{"failing-cataloger: unable to parse"}, reasons)
		}
	})

	t.Run("an error with no coordinates is attributed to the archive", func(t *testing.T) {
		failing := NewTask("bare-error-cataloger", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
			return errors.New("cataloger blew up")
		})

		tsk := NewArchiveCatalogerTask(cfg, []Task{failing}, newResolver, nil, nil)
		require.NotNil(t, tsk)

		s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
		require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)))

		require.Len(t, s.Artifacts.Unknowns, 1)
		reasons, ok := s.Artifacts.Unknowns[file.Coordinates{RealPath: "/outer.zip"}]
		require.True(t, ok, "an error with no location of its own belongs to the containing archive")
		assert.Equal(t, []string{"bare-error-cataloger: cataloger blew up"}, reasons)
	})

	t.Run("a panicking cataloger is recovered and recorded", func(t *testing.T) {
		// runTaskSafely converts the panic to an error, which now has somewhere to go
		panicking := NewTask("panicking-cataloger", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
			panic("nope")
		})

		tsk := NewArchiveCatalogerTask(cfg, []Task{panicking}, newResolver, nil, nil)
		require.NotNil(t, tsk)

		s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
		require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)),
			"a panic inside an archive must not fail the scan")

		reasons, ok := s.Artifacts.Unknowns[file.Coordinates{RealPath: "/outer.zip"}]
		require.True(t, ok)
		require.Len(t, reasons, 1)
		assert.Contains(t, reasons[0], "panicking-cataloger: nope")
	})
}

func Test_archiveCataloger_subPipelineUnknownsAreAddedNotReplaced(t *testing.T) {
	// mergeFileArtifacts appends to the shared SBOM's unknowns, so the ones a sub-cataloger wrote
	// into the scratch SBOM itself must survive alongside the one the failure produced
	outerZip := makeZip(t, map[string][]byte{"lib/thing.json": []byte("{}")})
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	preexisting := file.Coordinates{RealPath: "/lib/thing.json", ArchivePath: "outer.zip"}
	writer := NewTask("scratch-writer", func(_ context.Context, _ file.Resolver, builder sbomsync.Builder) error {
		builder.(sbomsync.Accessor).WriteToSBOM(func(s *sbom.SBOM) {
			s.Artifacts.Unknowns[preexisting] = append(s.Artifacts.Unknowns[preexisting], "recorded by the cataloger itself")
		})
		return nil
	})
	failing := NewTask("failing-cataloger", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		return errors.New("boom")
	})

	newResolver := newTarTestResolver
	tsk := NewArchiveCatalogerTask(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1), []Task{writer, failing}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)))

	assert.Equal(t, []string{"recorded by the cataloger itself"}, s.Artifacts.Unknowns[preexisting])
	assert.Equal(t, []string{"failing-cataloger: boom"}, s.Artifacts.Unknowns[file.Coordinates{RealPath: "/outer.zip"}])
}

func Test_archiveCataloger_manySmallArchivesAreEachCataloged(t *testing.T) {
	// the case the monotonic counter wrongly rejected: every archive is released before the next
	// begins, so a scan whose archives sum well past the disk limit never holds more than one of
	// them at a time and every one is cataloged
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

	var ran int
	countTask := NewTask("count-runs", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		ran++
		return nil
	})

	// one archive extracts 2000 bytes, so the limit holds one comfortably and the five together
	// would be four times over a counter that never fell
	cfg := cataloging.DefaultArchiveSearchConfig().
		WithMaxDepth(1).
		WithMaxDiskBytes(4000)

	newResolver := newTarTestResolver

	tsk := NewArchiveCatalogerTask(cfg, []Task{countTask}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)))

	assert.Equal(t, len(names), ran, "every archive must be cataloged: no two were ever held at once")
}

func Test_archiveCataloger_limitsFallWhenAnArchiveIsReleased(t *testing.T) {
	// a second archive the same size as the first is cataloged in full, which a counter would have
	// refused, and both limits are back at zero once the walk unwinds
	entry := bytes.Repeat([]byte("z"), 400)
	entries := map[string][]byte{}
	for i := range 5 {
		entries[fmt.Sprintf("e%d.bin", i)] = entry
	}

	rootDir := t.TempDir()
	for _, name := range []string{"one.zip", "two.zip"} {
		require.NoError(t, os.WriteFile(filepath.Join(rootDir, name), makeZip(t, entries), 0o600))
	}

	// each entry costs a header block plus a padded data block, and the tar carries an
	// end-of-archive marker: five entries of 400 bytes is 11 blocks. Room for one archive's tar and
	// not for two at once.
	cfg := cataloging.DefaultArchiveSearchConfig().
		WithMaxDepth(1).
		WithMaxDiskBytes(15 * 512)

	limiter := archive.NewLimiter(archive.DefaultLimits(cfg))

	// measured while the archive is still held: the resolver is built straight after extraction and
	// before anything is cleaned up
	var extracted []int
	var peakMemory int64
	newResolver := func(overflow archive.Overflow) (file.Resolver, archive.IndexResult, error) {
		resolver, indexed, err := newTarTestResolver(overflow)
		extracted = append(extracted, indexed.Records)
		if mem, _ := limiter.InUse(); mem > peakMemory {
			peakMemory = mem
		}
		return resolver, indexed, err
	}

	c := &archiveCataloger{
		cfg:         cfg,
		subPipeline: []Task{NewTask("noop", func(context.Context, file.Resolver, sbomsync.Builder) error { return nil })},
		extractors:  archive.DefaultExtractors(),
		limits:      archive.DefaultExtractionLimits(cfg),
		limiter:     limiter,
		newResolver: newResolver,
	}

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, c.catalog(context.Background(), dirTestResolver{dir: rootDir}, nil, 0, sbomsync.NewBuilder(s)))

	assert.Equal(t, []int{5, 5}, extracted,
		"both archives must extract in full: the first is released before the second is admitted")
	assert.Positive(t, peakMemory,
		"an archive within the memory limit is held in memory, so memory in use must rise")

	mem, disk := limiter.InUse()
	assert.Zero(t, mem, "the memory limit must fall back to nothing once the walk unwinds")
	assert.Zero(t, disk, "and so must the disk limit")
}

func Test_archiveCataloger_archiveExceedingTheDiskLimitIsSkipped(t *testing.T) {
	// the disk limit is terminal, so an archive whose own content will not fit is skipped rather
	// than waited for, and a sibling that does fit is cataloged in full
	oversized := makeZip(t, map[string][]byte{"payload.bin": incompressible(8000)})
	small := makeZip(t, map[string][]byte{"ok.txt": []byte("ok")})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "oversized.zip"), oversized, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "small.zip"), small, 0o600))

	// room for the small archive's own bytes and the tar its one entry is written into - a header
	// block, a padded data block and an end-of-archive marker - and nowhere near the oversized one
	diskLimit := int64(len(small)) + 8*512
	require.Greater(t, int64(len(oversized)), diskLimit, "the fixture must actually exceed the limit")

	var sawArchivePaths []string
	newResolver := func(overflow archive.Overflow) (file.Resolver, archive.IndexResult, error) {
		sawArchivePaths = append(sawArchivePaths, overflow.ArchivePath)
		return newTarTestResolver(overflow)
	}

	cfg := cataloging.DefaultArchiveSearchConfig().
		WithMaxDepth(1).
		WithMaxMemoryBytes(0). // every archive overflows, so its own bytes are charged to disk
		WithMaxDiskBytes(diskLimit)

	var ran int
	countTask := NewTask("count-runs", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		ran++
		return nil
	})

	tsk := NewArchiveCatalogerTask(cfg, []Task{countTask}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)),
		"reaching a limit must not fail the scan")

	assert.Equal(t, []string{"/small.zip"}, sawArchivePaths,
		"the oversized archive is skipped and the sibling is still cataloged")
	assert.Equal(t, 1, ran)
}

func Test_archiveCataloger_zeroDiskLimitAdmitsNoArchiveContent(t *testing.T) {
	// This case used to say "a zero disk limit skips what will not fit in memory": an archive's own
	// bytes were held in memory while the memory limit admitted them, and only what did not fit had
	// nowhere to go. It now says something stronger, because an archive's ENTRIES live in a file
	// whatever happened to the archive's own bytes: with no disk to write it, that file cannot be
	// created, so no archive's content can be admitted and every archive is skipped - the memory limit
	// notwithstanding.
	//
	// The scan still succeeds, and every skip is attributed to the archive that could not be placed,
	// which is the part that has not changed.
	oversized := makeZip(t, map[string][]byte{"payload.bin": incompressible(8000)})
	small := makeZip(t, map[string][]byte{"ok.txt": []byte("ok")})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "oversized.zip"), oversized, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "small.zip"), small, 0o600))

	// generous: even the small archive, which fits in memory with room to spare, has nowhere to put
	// its entries
	memoryLimit := int64(len(oversized) + len(small) + 1000)

	var sawArchivePaths []string
	newResolver := func(overflow archive.Overflow) (file.Resolver, archive.IndexResult, error) {
		sawArchivePaths = append(sawArchivePaths, overflow.ArchivePath)
		return newTarTestResolver(overflow)
	}

	cfg := cataloging.DefaultArchiveSearchConfig().
		WithMaxDepth(1).
		WithMaxMemoryBytes(memoryLimit).
		WithMaxDiskBytes(0) // nowhere to write the file an archive's entries live in

	var ran int
	countTask := NewTask("count-runs", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		ran++
		return nil
	})

	tsk := NewArchiveCatalogerTask(cfg, []Task{countTask}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)),
		"reaching the disk limit must not fail the scan")

	assert.Empty(t, sawArchivePaths,
		"with no disk there is nowhere for an archive's entries to go, so no archive is descended into")
	assert.Zero(t, ran)
}

func Test_archiveCataloger_bothLimitsZeroSkipsEveryArchiveAndSucceeds(t *testing.T) {
	// the degenerate configuration where nothing is admitted anywhere: every archive is skipped, and
	// that is a well-defined success rather than a failure
	entries := map[string][]byte{"ok.txt": []byte("ok")}
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "one.zip"), makeZip(t, entries), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "two.zip"), makeZip(t, entries), 0o600))

	var sawArchivePaths []string
	newResolver := func(overflow archive.Overflow) (file.Resolver, archive.IndexResult, error) {
		sawArchivePaths = append(sawArchivePaths, overflow.ArchivePath)
		return newTarTestResolver(overflow)
	}

	cfg := cataloging.DefaultArchiveSearchConfig().
		WithMaxDepth(1).
		WithMaxMemoryBytes(0).
		WithMaxDiskBytes(0)

	var ran int
	countTask := NewTask("count-runs", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		ran++
		return nil
	})

	tsk := NewArchiveCatalogerTask(cfg, []Task{countTask}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)),
		"both limits at zero is a real configuration, not a failure")

	assert.Empty(t, sawArchivePaths, "no archive content can be admitted anywhere, so every archive is skipped")
	assert.Zero(t, ran, "the sub-pipeline never runs since nothing was extracted")
}

func Test_archiveCataloger_nestedArchiveExceedingALimitIsSkippedNotBlocked(t *testing.T) {
	// the walk descends before it unwinds, so a parent is still holding its content while its
	// children are cataloged and nothing will be released while a child waits. Waiting for capacity
	// would be a deadlock, so a child that does not fit is skipped and the scan finishes.
	inner := makeZip(t, map[string][]byte{"payload.bin": incompressible(3000)})
	outer := makeZip(t, map[string][]byte{"inner.zip": inner})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outer, 0o600))

	// enough for the outer archive's own bytes plus the inner.zip it extracts, and not enough for
	// the inner archive's bytes on top of them
	diskLimit := int64(len(outer)+len(inner)) + 500
	require.Greater(t, int64(len(inner)), int64(500), "the inner archive must not fit in the slack")

	var sawArchivePaths []string
	newResolver := func(overflow archive.Overflow) (file.Resolver, archive.IndexResult, error) {
		sawArchivePaths = append(sawArchivePaths, overflow.ArchivePath)
		return newTarTestResolver(overflow)
	}

	cfg := cataloging.DefaultArchiveSearchConfig().
		WithMaxDepth(2).
		WithMaxMemoryBytes(0). // every archive overflows, so its own bytes are charged to disk
		WithMaxDiskBytes(diskLimit)

	noop := NewTask("noop", func(context.Context, file.Resolver, sbomsync.Builder) error { return nil })
	tsk := NewArchiveCatalogerTask(cfg, []Task{noop}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)))

	assert.Equal(t, []string{"/outer.zip"}, sawArchivePaths,
		"the parent is cataloged and the child it cannot afford is skipped rather than blocking")
}

// incompressible returns n bytes deflate cannot shrink, so an archive built from them has a size on
// disk predictable enough to size a limit against.
func incompressible(n int) []byte {
	b := make([]byte, n)
	x := uint32(12345)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	return b
}

// makeTarGz builds a gzipped tar in memory, in sorted entry order for the same reason makeZip does.
func makeTarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	require.NoError(t, writeTar(t, gw, entries))
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

// makeTar builds an uncompressed tar in memory.
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

// allFilesResolver is dirTestResolver without a filesystem id. Both sniff content the way a real
// resolver does, so which files reach the task is decided by what they are rather than by what the
// test wishes they were.
type allFilesResolver struct {
	file.Resolver
	dir string
}

func (a allFilesResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	return filesByMIMEType(a.dir, "", types...)
}

func (a allFilesResolver) FileContentsByLocation(loc file.Location) (io.ReadCloser, error) {
	return os.Open(filepath.Join(a.dir, filepath.FromSlash(loc.RealPath)))
}

func Test_archiveCataloger_discoverArchivesSelectsTarFamily(t *testing.T) {
	// every other task-level fixture is a zip, so the tar branch of FindExtractor had never been
	// reached through the task's own discovery
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
	captureTask := NewTask("capture", func(ctx context.Context, r file.Resolver, _ sbomsync.Builder) error {
		trav := archive.TraversalFromContext(ctx)
		require.NotNil(t, trav)

		// the contents are actually there, so the extraction really happened rather than the
		// traversal being built over an empty tree
		locs, err := r.FilesByGlob("**")
		require.NoError(t, err)
		assert.NotEmpty(t, locs, "expected contents inside %s", trav.VirtualPath)

		seen = append(seen, trav.VirtualPath)
		return nil
	})

	newResolver := newTarTestResolver

	tsk := NewArchiveCatalogerTask(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1), []Task{captureTask}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, tsk.Execute(context.Background(), allFilesResolver{dir: scanDir}, sbomsync.NewBuilder(s)))

	assert.ElementsMatch(t, []string{"/bundle.tar.gz", "/bundle.tgz", "/bundle.tar", "/bundle.zip"}, seen,
		"every tar-family archive must be reached, and the plain text file must not be")

	t.Run("the MIME types the tar family is sniffed as are in the set discovery asks for", func(t *testing.T) {
		// discoverArchives passes mimetype.ArchiveMIMETypeSet to FilesByMIMEType, so a tar type
		// missing from it makes the whole tar path unreachable no matter what the extractor can do
		for _, mt := range []string{"application/x-tar", "application/gzip", "application/x-gtar", "application/zip"} {
			assert.True(t, mimetype.ArchiveMIMETypeSet.Has(mt), "%s must be a candidate archive type", mt)
		}
	})
}

// recordingPublisher captures every event published to the bus during a test.
type recordingPublisher struct {
	events []partybus.Event
}

func (p *recordingPublisher) Publish(e partybus.Event) {
	p.events = append(p.events, e)
}

func Test_archiveCatalogerTask_publishesOneProgressRowForTheWholeWalk(t *testing.T) {
	// the sub-pipeline re-runs catalogers that start a progress row of their own, keyed by cataloger
	// name. Publishing those again per archive floods a consumer's UI with rows, and a consumer that
	// keys rows by ID (as the syft CLI does) replaces the live row for that ID, never renders the
	// replaced one again, and so never observes its completion - which hangs UI teardown. The whole
	// walk therefore reports through the single row this task starts for itself.
	inner := makeZip(t, map[string][]byte{"inner/file.txt": []byte("hello")})
	scanDir := t.TempDir()
	for _, name := range []string{"one.zip", "two.zip"} {
		require.NoError(t, os.WriteFile(filepath.Join(scanDir, name), inner, 0o600))
	}

	publisher := &recordingPublisher{}
	bus.Set(publisher)
	t.Cleanup(func() { bus.Set(nil) })

	// a task that starts a progress row the same way every package cataloger does
	var reported []string
	noisy := NewTask("noisy", func(ctx context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		p := bus.StartCatalogerTask(ctx, monitor.GenericTask{ID: "noisy"}, -1, "")
		p.AtomicStage.Set("working on something")

		// what the nested cataloger is doing reaches the row that is already on screen
		row := publisher.events[0].Value.(progress.StagedProgressable)
		reported = append(reported, row.Stage())

		// and the nested task finishing does not finish the row it reports into
		p.SetCompleted()
		assert.NotErrorIs(t, row.Error(), progress.ErrCompleted,
			"a sub-task completing must not complete the row it reports into")
		return nil
	})

	// the row's stage as each archive is about to be extracted: by then the previous archive's
	// sub-pipeline has finished, so the row must read the walk's own count rather than whatever the
	// last nested cataloger signed off with
	var stageAtExtraction []string
	newResolver := func(overflow archive.Overflow) (file.Resolver, archive.IndexResult, error) {
		stageAtExtraction = append(stageAtExtraction, publisher.events[0].Value.(progress.StagedProgressable).Stage())
		return newTarTestResolver(overflow)
	}

	tsk := NewArchiveCatalogerTask(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1), []Task{noisy}, newResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: scanDir}, sbomsync.NewBuilder(s)))

	var started []string
	for _, e := range publisher.events {
		if e.Type != event.CatalogerTaskStarted {
			continue
		}
		info, ok := e.Source.(monitor.GenericTask)
		require.True(t, ok, "expected a generic task as the event source")
		started = append(started, info.ID)
	}

	assert.Equal(t, []string{ArchiveCatalogerTaskName}, started,
		"only the archive cataloger's own row may be published, however many archives the walk enters")

	require.Len(t, publisher.events, 1)
	prog, ok := publisher.events[0].Value.(progress.StagedProgressable)
	require.True(t, ok)
	assert.ErrorIs(t, prog.Error(), progress.ErrCompleted, "the row must be completed, or a waiting consumer never finishes")
	assert.Equal(t, int64(2), prog.Current(), "the row counts every archive the walk entered")
	assert.Equal(t, "2 archives", prog.Stage(), "and says so once the walk is done")

	assert.Equal(t, []string{"working on something", "working on something"}, reported,
		"every nested run must report through the existing row")

	assert.Equal(t, []string{"", "1 archives"}, stageAtExtraction,
		"the row must take its stage back from the sub-pipeline once an archive is done")
}

func Test_archiveCataloger_reportsPeakUsageAndTheSlowestArchive(t *testing.T) {
	// the slowest archive is the one that spent the time itself. Inclusive time would name the outer
	// archive on every scan, since it contains everything below it, so the outer's own sub-pipeline
	// is made fast here and the inner's slow: the report must name the inner.
	innerJar := makeZip(t, map[string][]byte{"README.txt": []byte("inner")})
	outerZip := makeZip(t, map[string][]byte{"lib/inner.jar": innerJar})

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "outer.zip"), outerZip, 0o600))

	const innerWork = 40 * time.Millisecond
	slow := NewTask("slow-inside-the-inner-archive", func(ctx context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		if trav := archive.TraversalFromContext(ctx); trav != nil && strings.HasSuffix(trav.VirtualPath, "inner.jar") {
			time.Sleep(innerWork)
		}
		return nil
	})

	cfg := cataloging.DefaultArchiveSearchConfig().WithMaxDepth(3)
	limiter := archive.NewLimiter(archive.DefaultLimits(cfg))
	c := &archiveCataloger{
		cfg:         cfg,
		subPipeline: []Task{slow},
		extractors:  archive.DefaultExtractors(),
		limits:      archive.DefaultExtractionLimits(cfg),
		limiter:     limiter,
		newResolver: newTarTestResolver,
	}

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, c.catalog(context.Background(), dirTestResolver{dir: rootDir}, nil, 0, sbomsync.NewBuilder(s)))

	assert.Equal(t, "/outer.zip:lib/inner.jar", c.slowestPath,
		"the slowest archive is named by its full chain, not by its base name, and self time must exclude the archives nested inside")
	assert.GreaterOrEqual(t, c.slowest, innerWork)
	assert.Equal(t, int64(2), c.archivesSeen)

	// the peaks outlive the walk that set them, so they are still readable once everything is released
	peakMemory, _ := limiter.Peak()
	assert.Positive(t, peakMemory, "content held in memory must show on the peak")
	memory, disk := limiter.InUse()
	assert.Zero(t, memory)
	assert.Zero(t, disk)
}

func Test_archiveCataloger_slowestIsUnsetWhenNoArchiveIsCataloged(t *testing.T) {
	// a directory with nothing extractable in it: there is no archive to name, and the report must
	// not invent one
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "notes.txt"), []byte("not an archive"), 0o600))

	cfg := cataloging.DefaultArchiveSearchConfig().WithMaxDepth(2)
	c := &archiveCataloger{
		cfg:         cfg,
		subPipeline: []Task{NewTask("noop", func(context.Context, file.Resolver, sbomsync.Builder) error { return nil })},
		extractors:  archive.DefaultExtractors(),
		limits:      archive.DefaultExtractionLimits(cfg),
		limiter:     archive.NewLimiter(archive.DefaultLimits(cfg)),
		newResolver: newTarTestResolver,
	}

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, c.catalog(context.Background(), dirTestResolver{dir: rootDir}, nil, 0, sbomsync.NewBuilder(s)))

	assert.Empty(t, c.slowestPath)
	assert.Zero(t, c.archivesSeen)
	c.logStats() // must not panic with nothing to report
}

func Test_archiveCataloger_aMisnamedNonArchiveIsNotAnError(t *testing.T) {
	// `syft/nested-archive-cataloging#content-based-archive-detection`, scenario "misnamed
	// non-archive is not extracted": the name says archive, the content does not, and the scan says
	// nothing about it. It never becomes a candidate, because its content types it as text.
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "notes.zip"),
		[]byte("this is prose, not an archive, whatever the extension claims\n"), 0o600))

	var ran int
	countTask := NewTask("count-runs", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		ran++
		return nil
	})

	tsk := NewArchiveCatalogerTask(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(1),
		[]Task{countTask}, newTarTestResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	err := tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s))

	assert.NoError(t, err, "a file that is not an archive is not a failure to report")
	assert.Zero(t, ran, "and nothing is cataloged inside it")
}

func Test_archiveCataloger_catalogsAZipBehindALauncherScript(t *testing.T) {
	// end to end for the Spring Boot executable jar shape: a launcher script with a zip concatenated
	// onto it. Content sniffing types it text/x-shellscript, so it reaches the walk only through the
	// appended-archive candidate set, and it is an archive only because it ends in an
	// end-of-central-directory record.
	inner := makeZip(t, map[string][]byte{"nested/marker.txt": []byte("found me")})
	prefixed := append([]byte("#!/bin/bash\nexec java -jar \"$0\" \"$@\"\nexit 0\n"),
		makeZip(t, map[string][]byte{"BOOT-INF/lib/inner.jar": inner})...)

	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "app.jar"), prefixed, 0o600))

	var seen []string
	capture := NewTask("capture", func(ctx context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		if trav := archive.TraversalFromContext(ctx); trav != nil {
			seen = append(seen, trav.VirtualPath)
		}
		return nil
	})

	tsk := NewArchiveCatalogerTask(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(3),
		[]Task{capture}, newTarTestResolver, nil, nil)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	require.NoError(t, tsk.Execute(context.Background(), dirTestResolver{dir: rootDir}, sbomsync.NewBuilder(s)))

	assert.Equal(t, []string{"/app.jar", "/app.jar:BOOT-INF/lib/inner.jar"}, seen,
		"the stub must not hide the archive, and the walk must carry on into what it holds")
}

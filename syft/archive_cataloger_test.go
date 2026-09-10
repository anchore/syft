package syft

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

// markerCataloger is a stub package cataloger that emits one package for every "marker.txt" file it
// finds. It lets the archive-cataloger end-to-end test assert behavior without depending on the
// fixture format of any real language cataloger.
type markerCataloger struct{}

func (markerCataloger) Name() string { return "marker-cataloger" }

func (markerCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	locations, err := resolver.FilesByGlob("**/marker.txt")
	if err != nil {
		return nil, nil, err
	}
	var pkgs []pkg.Package
	for _, loc := range locations {
		p := pkg.Package{
			Name:      "marker-pkg",
			Version:   "1.0.0",
			Type:      pkg.BinaryPkg,
			Locations: file.NewLocationSet(loc),
		}
		p.SetID()
		pkgs = append(pkgs, p)
	}
	return pkgs, nil, nil
}

// TestArchiveCataloger_endToEnd scans a directory containing a zip that holds a marker file, with
// recursive archive cataloging enabled, and asserts that: (1) the package discovered inside the
// archive is stamped with the archive's nesting-chain FileSystemID, and (2) a file-level CONTAINS
// relationship links the archive to the discovered package.
func TestArchiveCataloger_endToEnd(t *testing.T) {
	scanDir := t.TempDir()
	writeTestZip(t, filepath.Join(scanDir, "app.zip"), map[string]string{"nested/marker.txt": "hello"})

	src, err := directorysource.New(directorysource.Config{Path: scanDir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	cfg := DefaultCreateSBOMConfig().
		WithoutCatalogers().
		WithCatalogers(pkgcataloging.NewCatalogerReference(markerCataloger{}, []string{"directory"}))
	cfg.Archive.MaxDepth = 1

	s, err := cfg.Create(context.Background(), src)
	require.NoError(t, err)

	pkgs := s.Artifacts.Packages.Sorted()
	require.Len(t, pkgs, 1, "expected exactly one package, discovered inside the archive")
	found := pkgs[0]
	assert.Equal(t, "marker-pkg", found.Name)

	locs := found.Locations.ToSlice()
	require.NotEmpty(t, locs)
	// root directory FSID is empty, so the chain starts with the relative archive path
	assert.Equal(t, "app.zip", locs[0].ArchivePath, "package location should carry the archive's FileSystemID")

	// a file-level CONTAINS relationship should link the archive file to the discovered package
	var hasContains bool
	for _, rel := range s.Relationships {
		if rel.Type != artifact.ContainsRelationship || rel.To.ID() != found.ID() {
			continue
		}
		coord, ok := rel.From.(file.Coordinates)
		if ok && strings.HasSuffix(coord.RealPath, "app.zip") {
			hasContains = true
		}
	}
	assert.True(t, hasContains, "expected a CONTAINS relationship from app.zip to the discovered package")
}

// TestArchiveCataloger_nestedRecursion validates depth-limited recursion and the FileSystemID
// nesting chain: a marker inside inner.zip inside outer.zip should be stamped with the full chain.
func TestArchiveCataloger_nestedRecursion(t *testing.T) {
	innerZip := buildZipBytes(t, map[string]string{"nested/marker.txt": "hello"})
	scanDir := t.TempDir()
	writeTestZipRaw(t, filepath.Join(scanDir, "outer.zip"), map[string][]byte{
		"deeper/inner.zip": innerZip,
	})

	src, err := directorysource.New(directorysource.Config{Path: scanDir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	cfg := DefaultCreateSBOMConfig().
		WithoutCatalogers().
		WithCatalogers(pkgcataloging.NewCatalogerReference(markerCataloger{}, []string{"directory"}))
	cfg.Archive.MaxDepth = 2

	s, err := cfg.Create(context.Background(), src)
	require.NoError(t, err)

	pkgs := s.Artifacts.Packages.Sorted()
	require.Len(t, pkgs, 1)
	locs := pkgs[0].Locations.ToSlice()
	require.NotEmpty(t, locs)
	assert.Equal(t, "outer.zip:deeper/inner.zip", locs[0].ArchivePath,
		"nested package location should carry the full archive nesting chain as its FileSystemID")
}

func writeTestZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	raw := make(map[string][]byte, len(files))
	for k, v := range files {
		raw[k] = []byte(v)
	}
	writeTestZipRaw(t, path, raw)
}

func writeTestZipRaw(t *testing.T, path string, files map[string][]byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, buildZipBytesRaw(t, files), 0o644))
}

func buildZipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	raw := make(map[string][]byte, len(files))
	for k, v := range files {
		raw[k] = []byte(v)
	}
	return buildZipBytesRaw(t, raw)
}

// buildZipBytesRaw writes entries in sorted name order. Extraction limits are enforced as the walk
// proceeds, so which entries land before a truncation depends on entry order; taking the order from
// the map would make any limit assertion flaky.
func buildZipBytesRaw(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range names {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write(files[name])
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// archiveScanConfig builds a CreateSBOMConfig limited to the given catalogers, with nested archive
// cataloging at the given depth (0 disables it).
func archiveScanConfig(depth int, catalogers ...pkg.Cataloger) *CreateSBOMConfig {
	refs := make([]pkgcataloging.CatalogerReference, 0, len(catalogers))
	for _, c := range catalogers {
		refs = append(refs, pkgcataloging.NewCatalogerReference(c, []string{"directory"}))
	}
	cfg := DefaultCreateSBOMConfig().WithoutCatalogers().WithCatalogers(refs...)
	cfg.Archive.MaxDepth = depth
	return cfg
}

// javaScanConfig builds a config whose java cataloger comes from the cataloging FACTORY rather than
// being handed in pre-built. That distinction matters: the yield flag that hands recursion to the
// archive task is derived onto the factory's PackagesConfig, so a pre-built cataloger passed via
// WithCatalogers keeps whatever config it was constructed with and never learns to yield.
//
// It selects only the java-tagged catalogers rather than taking the whole default set, because the
// default set includes the RPM cataloger, which needs a sqlite driver this test binary does not
// register.
func javaScanConfig(depth int) *CreateSBOMConfig {
	cfg := DefaultCreateSBOMConfig().
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults("java"))
	if depth > 0 {
		cfg = cfg.WithArchiveConfig(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(depth))
	}
	return cfg
}

func scanDirWith(t *testing.T, dir string, cfg *CreateSBOMConfig) *sbom.SBOM {
	t.Helper()
	src, err := directorysource.New(directorysource.Config{Path: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	s, err := cfg.Create(context.Background(), src)
	require.NoError(t, err)
	return s
}

// scanDirWithExclusions scans with the given exclusion patterns configured on the SOURCE, which is
// where exclusions live: this capability has no setting of its own, so this is the only way to
// configure them and the same call a real consumer makes.
func scanDirWithExclusions(t *testing.T, dir string, cfg *CreateSBOMConfig, exclude ...string) *sbom.SBOM {
	t.Helper()
	src, err := directorysource.New(directorysource.Config{
		Path:    dir,
		Exclude: source.ExcludeConfig{Paths: exclude},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	s, err := cfg.Create(context.Background(), src)
	require.NoError(t, err)
	return s
}

func jarBytes(t *testing.T, title, version string, extra map[string][]byte) []byte {
	t.Helper()
	entries := map[string][]byte{
		"META-INF/MANIFEST.MF": []byte(
			"Manifest-Version: 1.0\nImplementation-Title: " + title + "\nImplementation-Version: " + version + "\n",
		),
	}
	for k, v := range extra {
		entries[k] = v
	}
	return buildZipBytesRaw(t, entries)
}

func TestArchiveCataloger_jarInsideArchiveCatalogedOnce(t *testing.T) {
	// the failure this guards against is a DUPLICATE, not an error: before the archive task took
	// ownership of recursion, a jar inside a zip was reached both by the task's walk and by the java
	// cataloger's own unarchiving. Count, do not assert presence.
	dep := jarBytes(t, "nested-lib", "2.0", nil)

	tests := []struct {
		name      string
		container string
		entry     string
	}{
		{name: "jar inside a zip", container: "bundle.zip", entry: "lib/nested-lib-2.0.jar"},
		{name: "jar inside a war", container: "app.war", entry: "WEB-INF/lib/nested-lib-2.0.jar"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanDir := t.TempDir()
			writeTestZipRaw(t, filepath.Join(scanDir, tt.container), map[string][]byte{tt.entry: dep})

			s := scanDirWith(t, scanDir, javaScanConfig(3))

			var count int
			for _, p := range s.Artifacts.Packages.Sorted() {
				if p.Name == "nested-lib" {
					count++
				}
			}
			assert.Equal(t, 1, count, "the nested jar's package must be cataloged exactly once")
		})
	}
}

func TestArchiveCataloger_javaVirtualPathUnchangedByMechanism(t *testing.T) {
	// these colon-delimited strings appear in already-published SBOMs, so the package must be
	// reported under the same virtual path whichever mechanism reached it
	dep := jarBytes(t, "nested-lib", "2.0", nil)
	scanDir := t.TempDir()
	writeTestZipRaw(t, filepath.Join(scanDir, "app.war"), map[string][]byte{
		"WEB-INF/lib/nested-lib-2.0.jar": dep,
	})

	virtualPaths := func(t *testing.T, depth int) map[string]string {
		t.Helper()
		s := scanDirWith(t, scanDir, javaScanConfig(depth))

		out := map[string]string{}
		for _, p := range s.Artifacts.Packages.Sorted() {
			if metadata, ok := p.Metadata.(pkg.JavaArchive); ok {
				out[p.Name] = metadata.VirtualPath
			}
		}
		return out
	}

	off := virtualPaths(t, 0)
	on := virtualPaths(t, 3)

	require.Contains(t, off, "nested-lib", "the java cataloger's own recursion must find it when the feature is off")
	require.Contains(t, on, "nested-lib", "the archive cataloger must find it when the feature is on")
	// this equality IS the compatibility guarantee: the string is in already-published SBOMs, so a
	// package reached through the archive cataloger must not be reported under a different virtual
	// path than the java cataloger's own recursion reported for it
	assert.Equal(t, off["nested-lib"], on["nested-lib"],
		"the nested jar's virtual path must be byte-identical between the two mechanisms")

	// and the format itself is the historical colon-delimited one. For a directory source the
	// archive's access path is relative, so there is no leading separator on the chain.
	assert.Equal(t, "app.war:WEB-INF/lib/nested-lib-2.0.jar", on["nested-lib"])
}

func TestArchiveCataloger_archiveContentsDoNotLeakIntoParentTree(t *testing.T) {
	scanDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(scanDir, "app"), 0o755))
	writeTestZip(t, filepath.Join(scanDir, "app", "data.zip"), map[string]string{"nested/marker.txt": "hello"})

	s := scanDirWith(t, scanDir, archiveScanConfig(1, markerCataloger{}))

	for _, p := range s.Artifacts.Packages.Sorted() {
		for _, loc := range p.Locations.ToSlice() {
			// the nested file's path is relative to the archive, and the FileSystemID says which
			// archive. A joined or flattened path would mean the archive's contents were smeared
			// into the parent's tree, which is what the rejected resolver-recursion approach did.
			assert.NotContains(t, loc.RealPath, "data.zip/")
			assert.NotEqual(t, "/app/nested/marker.txt", loc.RealPath)
			assert.Equal(t, "app/data.zip", loc.ArchivePath)
		}
	}
}

func TestArchiveCataloger_siblingArchivesDoNotCollide(t *testing.T) {
	// two archives containing the same internal path: the file tables are map[file.Coordinates]...,
	// so without a distinct FileSystemID the second write silently overwrites the first and one
	// package disappears with no error anywhere
	scanDir := t.TempDir()
	writeTestZip(t, filepath.Join(scanDir, "one.zip"), map[string]string{"nested/marker.txt": "from one"})
	writeTestZip(t, filepath.Join(scanDir, "two.zip"), map[string]string{"nested/marker.txt": "from two"})

	s := scanDirWith(t, scanDir, archiveScanConfig(1, markerCataloger{}))

	// note: the two markers are the same package by syft's identity rules (same name, version and
	// type), so they merge into one package carrying two locations. That merge is pre-existing
	// behavior and is not what this test is about - what matters is that the two LOCATIONS survive
	// as distinct coordinates instead of one overwriting the other.
	fsIDs := strset.New()
	var locCount int
	for _, p := range s.Artifacts.Packages.Sorted() {
		if p.Name != "marker-pkg" {
			continue
		}
		for _, loc := range p.Locations.ToSlice() {
			locCount++
			fsIDs.Add(loc.ArchivePath)
			assert.Equal(t, "nested/marker.txt", loc.RealPath,
				"the paths are identical, which is exactly why the FileSystemID has to differ")
		}
	}

	assert.Equal(t, 2, locCount, "both archives' markers must survive as distinct locations")
	assert.ElementsMatch(t, []string{"one.zip", "two.zip"}, fsIDs.List(),
		"each archive must produce a distinct FileSystemID")
}

func TestArchiveCataloger_containsEdgesChainAcrossLevels(t *testing.T) {
	innerZip := buildZipBytes(t, map[string]string{"nested/marker.txt": "hello"})
	scanDir := t.TempDir()
	writeTestZipRaw(t, filepath.Join(scanDir, "outer.zip"), map[string][]byte{"deeper/inner.zip": innerZip})

	// file cataloging is on deliberately: the archive-to-file edges are recorded for the files the
	// FILE catalogers found inside an archive, so without them there is no coordinate for inner.zip
	// to hang an edge on and only the archive-to-package edges exist
	cfg := archiveScanConfig(2, markerCataloger{}).
		WithFilesConfig(filecataloging.Config{Selection: file.AllFilesSelection})
	s := scanDirWith(t, scanDir, cfg)

	// an edge from outer.zip to inner.zip (file-to-file), and one from inner.zip to the package
	var outerToInner, innerToPkg bool
	for _, rel := range s.Relationships {
		if rel.Type != artifact.ContainsRelationship {
			continue
		}
		from, ok := rel.From.(file.Coordinates)
		if !ok {
			continue
		}
		if to, ok := rel.To.(file.Coordinates); ok {
			if strings.HasSuffix(from.RealPath, "outer.zip") && strings.HasSuffix(to.RealPath, "inner.zip") {
				outerToInner = true
			}
			continue
		}
		if p, ok := rel.To.(pkg.Package); ok && p.Name == "marker-pkg" {
			if strings.HasSuffix(from.RealPath, "inner.zip") {
				innerToPkg = true
			}
		}
	}

	assert.True(t, outerToInner, "expected a CONTAINS edge from outer.zip to inner.zip")
	assert.True(t, innerToPkg, "expected a CONTAINS edge from inner.zip to the nested package")
}

func TestArchiveCataloger_truncationRetainsWhatWasFound(t *testing.T) {
	// a bound must truncate, not discard: the marker extracted before the disk limit filled stays in
	// the SBOM, and a small sibling archive is cataloged in full because the first archive was
	// released before it started
	big := bytes.Repeat([]byte("x"), 8192)
	scanDir := t.TempDir()
	writeTestZipRaw(t, filepath.Join(scanDir, "oversized.zip"), map[string][]byte{
		"a/marker.txt":  []byte("small enough"),
		"b/payload.bin": big,
	})
	writeTestZip(t, filepath.Join(scanDir, "small.zip"), map[string]string{"nested/marker.txt": "fine"})

	cfg := archiveScanConfig(1, markerCataloger{})
	cfg.Archive = cfg.Archive.WithMaxDiskBytes(1024)

	s := scanDirWith(t, scanDir, cfg)

	fsIDs := strset.New()
	for _, p := range s.Artifacts.Packages.Sorted() {
		for _, loc := range p.Locations.ToSlice() {
			fsIDs.Add(loc.ArchivePath)
		}
	}

	assert.True(t, fsIDs.Has("oversized.zip"),
		"the marker extracted before the limit must survive rather than the archive being discarded")
	assert.True(t, fsIDs.Has("small.zip"),
		"one archive hitting its limit must not affect another")
}

func TestArchiveCataloger_detectionIsContentBased(t *testing.T) {
	marker := map[string]string{"nested/marker.txt": "hello"}

	t.Run("extensionless and renamed archives are extracted", func(t *testing.T) {
		scanDir := t.TempDir()
		// no extension at all, and an extension that says something else entirely
		require.NoError(t, os.WriteFile(filepath.Join(scanDir, "bundle"), buildZipBytes(t, marker), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(scanDir, "data.bin"), buildZipBytes(t, marker), 0o644))

		s := scanDirWith(t, scanDir, archiveScanConfig(1, markerCataloger{}))

		fsIDs := strset.New()
		for _, p := range s.Artifacts.Packages.Sorted() {
			for _, loc := range p.Locations.ToSlice() {
				fsIDs.Add(loc.ArchivePath)
			}
		}
		assert.True(t, fsIDs.Has("bundle"), "an extensionless zip must be detected by content")
		assert.True(t, fsIDs.Has("data.bin"), "a renamed zip must be detected by content")
	})

	t.Run("a misnamed non-archive is not extracted and is not an error", func(t *testing.T) {
		scanDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(scanDir, "notes.zip"), []byte("just some text"), 0o644))

		s := scanDirWith(t, scanDir, archiveScanConfig(1, markerCataloger{}))
		assert.Empty(t, s.Artifacts.Packages.Sorted())
	})
}

// TestArchiveCataloger_exclusionsAreTheScansOwn covers the whole of
// exclusions-apply-by-pattern-scope from the outside: there is no archive-specific exclusion
// setting, and the scan's own patterns decide, by their shape, whether they reach inside an archive.
func TestArchiveCataloger_exclusionsAreTheScansOwn(t *testing.T) {
	marker := map[string]string{"nested/marker.txt": "hello"}

	t.Run("a recursive pattern reaches inside archives", func(t *testing.T) {
		// the marker is INSIDE the archive, so nothing but an exclusion applied to the archive's own
		// index can remove it: a filter over the scan root never sees this path at all
		scanDir := t.TempDir()
		writeTestZip(t, filepath.Join(scanDir, "app.zip"), marker)

		s := scanDirWithExclusions(t, scanDir, archiveScanConfig(1, markerCataloger{}), "**/marker.txt")
		assert.Empty(t, s.Artifacts.Packages.Sorted(),
			"a pattern matching at any depth must exclude a file inside an archive")
	})

	t.Run("a root-anchored pattern does not reach inside archives", func(t *testing.T) {
		// the same relative path exists twice: once at the scan root, once inside the archive. An
		// anchored pattern names the first and says nothing about the second
		scanDir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(scanDir, "nested"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(scanDir, "nested", "marker.txt"), []byte("at the root"), 0o644))
		writeTestZip(t, filepath.Join(scanDir, "app.zip"), marker)

		s := scanDirWithExclusions(t, scanDir, archiveScanConfig(1, markerCataloger{}), "./nested/marker.txt")

		var fsIDs []string
		for _, p := range s.Artifacts.Packages.Sorted() {
			for _, loc := range p.Locations.ToSlice() {
				fsIDs = append(fsIDs, loc.ArchivePath)
			}
		}
		assert.Equal(t, []string{"app.zip"}, fsIDs,
			"the file at the scan root must be excluded and the one inside the archive kept")
	})

	t.Run("excluding an archive's own extension stops it being descended into", func(t *testing.T) {
		// this is what replaces the removed extension list: the archive is not extracted, it is still
		// an ordinary file, and nothing about it is an error
		scanDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(scanDir, "pkg.rpm"), buildZipBytes(t, marker), 0o644))

		s := scanDirWithExclusions(t, scanDir, archiveScanConfig(1, markerCataloger{}), "**/*.rpm")
		assert.Empty(t, s.Artifacts.Packages.Sorted(),
			"an archive whose own path is excluded must not be extracted")
	})

	t.Run("a nested archive is excluded at its own level", func(t *testing.T) {
		// outer.zip is not excluded and is cataloged; inner.zip is, so it is absent from outer's own
		// filesystem, which is what makes it neither extracted nor recordable as a file. Asserted
		// through the resolver rather than through the file catalogers: absence from the index is
		// upstream of every consumer, so it settles both halves at once
		innerZip := buildZipBytes(t, marker)
		scanDir := t.TempDir()
		writeTestZipRaw(t, filepath.Join(scanDir, "outer.zip"), map[string][]byte{
			"deeper/inner.zip": innerZip,
			"outer/marker.txt": []byte("hello"),
		})

		var seen []string
		probe := resolverProbeCataloger{
			glob: "**/*.zip",
			record: func(paths []string) {
				seen = append(seen, paths...)
			},
		}
		s := scanDirWithExclusions(t, scanDir, archiveScanConfig(2, markerCataloger{}, probe), "**/inner.zip")

		var fsIDs []string
		for _, p := range s.Artifacts.Packages.Sorted() {
			for _, loc := range p.Locations.ToSlice() {
				fsIDs = append(fsIDs, loc.ArchivePath)
			}
		}
		assert.Equal(t, []string{"outer.zip"}, fsIDs,
			"the outer archive must still be cataloged and the inner one must contribute nothing")

		for _, path := range seen {
			assert.NotContains(t, path, "inner.zip",
				"the excluded inner archive must be absent from the outer archive's filesystem")
		}
		assert.NotEmpty(t, seen, "the probe must have seen the outer archive at the scan root")
	})

	t.Run("matching follows the scan's own case sensitivity", func(t *testing.T) {
		// worth pinning because it differs from the removed extension list, which lower-cased both
		// sides. An exclusion now behaves the same inside an archive as it does anywhere else in a
		// scan, which is the point of using the scan's own patterns; a caller who wants both cases
		// says so in the pattern, the way they would for any other exclusion
		scanDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(scanDir, "PKG.RPM"), buildZipBytes(t, marker), 0o644))

		kept := scanDirWithExclusions(t, scanDir, archiveScanConfig(1, markerCataloger{}), "**/*.rpm")
		assert.NotEmpty(t, kept.Artifacts.Packages.Sorted(),
			"a lower-case pattern must not match an upper-case name")

		excluded := scanDirWithExclusions(t, scanDir, archiveScanConfig(1, markerCataloger{}), "**/*.[rR][pP][mM]")
		assert.Empty(t, excluded.Artifacts.Packages.Sorted(),
			"the case-insensitive intent is expressible as an ordinary pattern")
	})

	t.Run("no exclusions means nothing is excluded", func(t *testing.T) {
		scanDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(scanDir, "pkg.rpm"), buildZipBytes(t, marker), 0o644))

		s := scanDirWith(t, scanDir, archiveScanConfig(1, markerCataloger{}))
		assert.NotEmpty(t, s.Artifacts.Packages.Sorted(),
			"with no patterns configured every detected archive stays eligible")
	})

	t.Run("an excluded file is absent from the filesystem, not present and skipped", func(t *testing.T) {
		// the distinction the whole mechanism rests on: an excluded entry is not in the archive's
		// index, so nothing downstream can resolve it by path or by glob
		scanDir := t.TempDir()
		writeTestZip(t, filepath.Join(scanDir, "app.zip"), map[string]string{
			"nested/marker.txt": "hello",
			"nested/keep.txt":   "hello",
		})

		var seen []string
		probe := resolverProbeCataloger{
			glob: "**/*.txt",
			record: func(paths []string) {
				seen = append(seen, paths...)
			},
		}
		scanDirWithExclusions(t, scanDir, archiveScanConfig(1, probe), "**/marker.txt")

		assert.Contains(t, seen, "nested/keep.txt")
		assert.NotContains(t, seen, "nested/marker.txt",
			"an excluded path must not be resolvable from the archive's filesystem at all")
	})
}

// TestArchiveCataloger_exclusionPatternPrecedence covers every-boundary-populates-the-patterns, which
// superseded the single-writer clause of patterns-ride-the-archive-config:
// cataloging.ArchiveSearchConfig.ExclusionPatterns is still a derived field (no yaml/json/mapstructure
// tag - there is still no key to supply a second, competing list through), but it is no longer written
// only by CreateSBOM. cmd/syft/internal/options.Catalog.ToArchiveConfig is the other boundary, filling
// it from the CLI's --exclude flag, and precedence between the two is defined rather than left to
// ordering: a value already present is never overwritten, and CreateSBOM consults the source only to
// fill an empty field.
func TestArchiveCataloger_exclusionPatternPrecedence(t *testing.T) {
	marker := map[string]string{"nested/marker.txt": "hello"}

	t.Run("a value already present is not overwritten by the source", func(t *testing.T) {
		scanDir := t.TempDir()
		writeTestZip(t, filepath.Join(scanDir, "app.zip"), marker)

		cfg := archiveScanConfig(1, markerCataloger{})
		cfg.Archive.ExclusionPatterns = []string{"**/marker.txt"}

		// the source publishes a different, non-matching pattern - if the source won, this would
		// have no effect on the caller-supplied value
		s := scanDirWithExclusions(t, scanDir, cfg, "**/does-not-exist.txt")
		assert.Empty(t, s.Artifacts.Packages.Sorted(),
			"a value already present on the config must be what is applied, not overwritten by what the source publishes")
	})

	t.Run("an empty field is filled from the source", func(t *testing.T) {
		// the configure-only-your-source path: a consumer who never touches ExclusionPatterns
		// directly still gets the source's own patterns applied inside archives
		scanDir := t.TempDir()
		writeTestZip(t, filepath.Join(scanDir, "app.zip"), marker)

		cfg := archiveScanConfig(1, markerCataloger{})

		s := scanDirWithExclusions(t, scanDir, cfg, "**/marker.txt")
		assert.Empty(t, s.Artifacts.Packages.Sorted(),
			"an empty field must be filled from the source's own published patterns")
	})

	t.Run("an empty field with no source exclusions excludes nothing", func(t *testing.T) {
		scanDir := t.TempDir()
		writeTestZip(t, filepath.Join(scanDir, "app.zip"), marker)

		cfg := archiveScanConfig(1, markerCataloger{})

		s := scanDirWith(t, scanDir, cfg)
		assert.NotEmpty(t, s.Artifacts.Packages.Sorted(),
			"with nothing configured on either boundary, no exclusion should apply")
	})
}

// resolverProbeCataloger reports what the resolver it was handed can actually see, which is how the
// difference between "absent from the index" and "present and skipped" is observed from a scan.
type resolverProbeCataloger struct {
	glob   string
	record func([]string)
}

func (resolverProbeCataloger) Name() string { return "resolver-probe-cataloger" }

func (c resolverProbeCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	locations, err := resolver.FilesByGlob(c.glob)
	if err != nil {
		return nil, nil, err
	}
	var paths []string
	for _, loc := range locations {
		paths = append(paths, loc.RealPath)
	}
	c.record(paths)
	return nil, nil, nil
}

func TestArchiveCataloger_leavesNothingBehind(t *testing.T) {
	// extracted content is written outside the scanned source and must not survive the scan, so a
	// long-running process scanning many archives does not accumulate temp trees
	innerZip := buildZipBytes(t, map[string]string{"nested/marker.txt": "hello"})
	scanDir := t.TempDir()
	writeTestZipRaw(t, filepath.Join(scanDir, "outer.zip"), map[string][]byte{"deeper/inner.zip": innerZip})
	// a corrupt archive so the failure path's cleanup is exercised too
	require.NoError(t, os.WriteFile(filepath.Join(scanDir, "corrupt.zip"), []byte("PK\x03\x04 truncated"), 0o644))

	before := archiveTempDirs(t)

	scanDirWith(t, scanDir, archiveScanConfig(2, markerCataloger{}))

	assert.ElementsMatch(t, before, archiveTempDirs(t),
		"no syft-archive-* temp dir may survive the scan, including for the archive that failed")

	// and nothing may be written into the directory under scan
	var found []string
	require.NoError(t, filepath.WalkDir(scanDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(scanDir, path)
		if relErr != nil {
			return relErr
		}
		found = append(found, rel)
		return nil
	}))
	assert.ElementsMatch(t, []string{"outer.zip", "corrupt.zip"}, found,
		"nothing new may appear under the scanned directory")
}

func archiveTempDirs(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(os.TempDir())
	require.NoError(t, err)

	var out []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "syft-archive-") {
			out = append(out, entry.Name())
		}
	}
	return out
}

func TestArchiveCataloger_unicodeEntryNamesSurviveToOutput(t *testing.T) {
	// entry names reach the FileSystemID and then the encoded SBOM; a mangled one is a corrupt
	// identifier rather than a visible failure
	innerZip := buildZipBytes(t, map[string]string{"nested/marker.txt": "hello"})
	scanDir := t.TempDir()
	writeTestZipRaw(t, filepath.Join(scanDir, "outer.zip"), map[string][]byte{
		"日本語/café-🎉/inner.zip": innerZip,
	})

	s := scanDirWith(t, scanDir, archiveScanConfig(2, markerCataloger{}))

	pkgs := s.Artifacts.Packages.Sorted()
	require.Len(t, pkgs, 1)
	locs := pkgs[0].Locations.ToSlice()
	require.NotEmpty(t, locs)
	assert.Equal(t, "outer.zip:日本語/café-🎉/inner.zip", locs[0].ArchivePath)
	assert.True(t, utf8.ValidString(locs[0].ArchivePath))
}

func TestArchiveCataloger_libraryParity(t *testing.T) {
	// the library entry point must give a Go consumer the same behavior as a CLI user, and must not
	// silently replace anything the consumer set on the package cataloger config
	dep := jarBytes(t, "nested-lib", "2.0", nil)
	scanDir := t.TempDir()
	writeTestZipRaw(t, filepath.Join(scanDir, "bundle.zip"), map[string][]byte{"lib/nested-lib-2.0.jar": dep})

	countNestedLib := func(t *testing.T, s *sbom.SBOM) int {
		t.Helper()
		var n int
		for _, p := range s.Artifacts.Packages.Sorted() {
			if p.Name == "nested-lib" {
				n++
			}
		}
		return n
	}

	t.Run("WithArchiveConfig enables the feature and hands java its yield", func(t *testing.T) {
		s := scanDirWith(t, scanDir, javaScanConfig(3))
		assert.Equal(t, 1, countNestedLib(t, s), "reached exactly once, via the archive cataloger")
	})

	t.Run("setting only java's own depth neither enables the feature nor breaks java", func(t *testing.T) {
		// java's squash-inlined MaxDepth is a config field a consumer can set; it must have no
		// effect on recursion ownership, and must not be overwritten either
		supplied := java.DefaultArchiveCatalogerConfig()
		supplied.ArchiveSearchConfig = supplied.ArchiveSearchConfig.WithMaxDepth(3)

		cfg := javaScanConfig(0).WithPackagesConfig(pkgcataloging.Config{JavaArchive: supplied})

		s := scanDirWith(t, scanDir, cfg)
		// the archive task never ran, so java's own recursion is what found it - once
		assert.Equal(t, 1, countNestedLib(t, s), "java must keep recursing itself")
		assert.Equal(t, 3, cfg.Packages.JavaArchive.MaxDepth, "the consumer's value must survive")
	})
}

func TestArchiveCataloger_noExtractionPathReachesTheSBOM(t *testing.T) {
	// covers syft/archive-content-identity#nested-paths-are-archive-relative. AllLocations emitted
	// the resolver's own root unrelativized, and filemetadata.Cataloger records every location it is
	// handed, so a coordinate whose RealPath was the extraction temp dir reached FileMetadata, was
	// merged into the shared SBOM, and gained a CONTAINS edge. File cataloging must be on: that is
	// the only path that enumerates all locations rather than searching for them.
	innerZip := buildZipBytes(t, map[string]string{"nested/marker.txt": "hello"})
	scanDir := t.TempDir()
	writeTestZipRaw(t, filepath.Join(scanDir, "outer.zip"), map[string][]byte{"deeper/inner.zip": innerZip})

	// the resolver normalizes its root with EvalSymlinks, so the scan root it reports is the
	// resolved path. On macOS t.TempDir() sits under /var, a symlink to /private/var, so comparing
	// against the unresolved value fails there while passing on linux.
	resolvedScanDir, err := filepath.EvalSymlinks(scanDir)
	require.NoError(t, err)

	cfg := archiveScanConfig(2, markerCataloger{}).
		WithFilesConfig(filecataloging.Config{Selection: file.AllFilesSelection})
	s := scanDirWith(t, scanDir, cfg)

	// every path syft can report about this scan, from every table and both ends of every edge
	var paths []string
	for coords := range s.Artifacts.FileMetadata {
		paths = append(paths, coords.RealPath)
	}
	for _, p := range s.Artifacts.Packages.Sorted() {
		for _, loc := range p.Locations.ToSlice() {
			paths = append(paths, loc.RealPath, loc.AccessPath)
		}
	}
	for _, rel := range s.Relationships {
		for _, end := range []artifact.Identifiable{rel.From, rel.To} {
			if coords, ok := end.(file.Coordinates); ok {
				paths = append(paths, coords.RealPath)
			}
		}
	}
	require.NotEmpty(t, paths)

	for _, p := range paths {
		assert.NotContains(t, p, "syft-archive-",
			"an extraction directory reached the SBOM at %q", p)
		// the storage shape is an implementation detail of the scan, so the file an archive's entries
		// were overflowed into must not name itself either - in a path, or as a segment of one
		assert.NotContains(t, p, "contents.tar",
			"the file holding an archive's entries reached the SBOM at %q", p)
		if filepath.IsAbs(p) {
			// the scan root itself is reported absolute by the directory resolver, and has been
			// since long before this feature: it is the path the user asked for. Anything else
			// absolute is a filesystem this feature invented leaking its own root.
			assert.Equal(t, resolvedScanDir, p, "only the scanned directory itself may be reported absolute")
		}
	}
}

func TestArchiveCataloger_repeatedScansAgreeOnNestedPaths(t *testing.T) {
	// the reproducibility property the requirement exists for: extraction directories are created
	// fresh per run, so anything of theirs that reaches output makes two scans of identical input
	// disagree
	innerZip := buildZipBytes(t, map[string]string{"nested/marker.txt": "hello"})
	scanDir := t.TempDir()
	writeTestZipRaw(t, filepath.Join(scanDir, "outer.zip"), map[string][]byte{"deeper/inner.zip": innerZip})

	scan := func(t *testing.T) []string {
		t.Helper()
		cfg := archiveScanConfig(2, markerCataloger{}).
			WithFilesConfig(filecataloging.Config{Selection: file.AllFilesSelection})
		s := scanDirWith(t, scanDir, cfg)

		var out []string
		for coords := range s.Artifacts.FileMetadata {
			out = append(out, coords.ArchivePath+"|"+coords.RealPath)
		}
		sort.Strings(out)
		return out
	}

	first := scan(t)
	require.NotEmpty(t, first)
	assert.Equal(t, first, scan(t))
}

// buildTarGzBytes builds a gzipped tar in memory, in sorted entry order.
func buildTarGzBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	writeTarEntries(t, gw, files)
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

// buildTarBytes builds an uncompressed tar in memory.
func buildTarBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writeTarEntries(t, &buf, files)
	return buf.Bytes()
}

func writeTarEntries(t *testing.T, w io.Writer, files map[string][]byte) {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	tw := tar.NewWriter(w)
	for _, name := range names {
		body := files[name]
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}))
		_, err := tw.Write(body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
}

func TestArchiveCataloger_tarFamilyIsCatalogedEndToEnd(t *testing.T) {
	// nothing asserted the tar path end to end: the extensionless-archive case builds a ZIP named
	// "bundle", so TarExtractor was only ever reached by its own unit tests. The compound extension
	// is the interesting one - the archive is saved to a temp file before detection and the basename
	// is preserved specifically so ".tar.gz" survives that round trip.
	dep := jarBytes(t, "tar-nested-lib", "3.1", nil)
	entry := map[string][]byte{"lib/tar-nested-lib-3.1.jar": dep}

	for name, body := range map[string][]byte{
		"bundle.tar.gz": buildTarGzBytes(t, entry),
		"bundle.tgz":    buildTarGzBytes(t, entry),
		"bundle.tar":    buildTarBytes(t, entry),
	} {
		t.Run(name, func(t *testing.T) {
			scanDir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(scanDir, name), body, 0o644))

			s := scanDirWith(t, scanDir, javaScanConfig(2))

			var count int
			var virtualPath string
			for _, p := range s.Artifacts.Packages.Sorted() {
				if p.Name != "tar-nested-lib" {
					continue
				}
				count++
				if metadata, ok := p.Metadata.(pkg.JavaArchive); ok {
					virtualPath = metadata.VirtualPath
				}
			}
			require.Equal(t, 1, count, "the jar inside the tar must be cataloged exactly once")
			assert.Equal(t, name+":lib/tar-nested-lib-3.1.jar", virtualPath)
		})
	}
}

func TestArchiveCataloger_legacySearchSettingsAreSuperseded(t *testing.T) {
	// syft/nested-archive-cataloging#legacy-archive-search-settings-are-superseded. The row that
	// matters is nested-on with both settings false: it looks like a bug and is not, so a future
	// change that "fixes" it is changing a requirement.
	dep := jarBytes(t, "legacy-lib", "1.2", nil)
	entry := map[string][]byte{"lib/legacy-lib-1.2.jar": dep}

	containers := map[string][]byte{
		"bundle.zip":    buildZipBytesRaw(t, entry),
		"bundle.tar.gz": buildTarGzBytes(t, entry),
	}

	// with the feature off, java's own wrapped-archive parsers are what reach the jar, and those are
	// gated by these two settings: indexed covers the zip, unindexed covers the tar family
	found := func(t *testing.T, container string, depth int, searchSettings *bool) bool {
		t.Helper()
		scanDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(scanDir, container), containers[container], 0o644))

		cfg := javaScanConfig(depth)
		if searchSettings != nil {
			// these two settings only ever reach the java cataloger's wrapped-archive parser
			// registrations, which is where the CLI's search-indexed-archives and
			// search-unindexed-archives land as well
			packages := cfg.Packages
			packages.JavaArchive.IncludeIndexedArchives = *searchSettings
			packages.JavaArchive.IncludeUnindexedArchives = *searchSettings
			cfg = cfg.WithPackagesConfig(packages)
		}

		for _, p := range scanDirWith(t, scanDir, cfg).Artifacts.Packages.Sorted() {
			if p.Name == "legacy-lib" {
				return true
			}
		}
		return false
	}

	yes, no := true, false

	for _, tt := range []struct {
		name           string
		depth          int
		searchSettings *bool
		wantZip        bool
		wantTarGz      bool
	}{
		{name: "off, both settings true", depth: 0, searchSettings: &yes, wantZip: true, wantTarGz: true},
		{name: "off, both settings false", depth: 0, searchSettings: &no, wantZip: false, wantTarGz: false},
		{name: "on, both settings true", depth: 2, searchSettings: &yes, wantZip: true, wantTarGz: true},
		// the load-bearing cell
		{name: "on, both settings false", depth: 2, searchSettings: &no, wantZip: true, wantTarGz: true},
		// and what real users hit: unindexed defaults to false, so the tar.gz is cataloged with a
		// setting whose documented meaning says it should not be
		{name: "on, settings untouched", depth: 2, searchSettings: nil, wantZip: true, wantTarGz: true},
		{name: "off, settings untouched", depth: 0, searchSettings: nil, wantZip: true, wantTarGz: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantZip, found(t, "bundle.zip", tt.depth, tt.searchSettings), "zip")
			assert.Equal(t, tt.wantTarGz, found(t, "bundle.tar.gz", tt.depth, tt.searchSettings), "tar.gz")
		})
	}
}

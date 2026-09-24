package syft

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

// Every CreateSBOM call pays to compile the license scanner, so the end-to-end behavior is asserted
// over one scan of one fixture directory rather than a scan per claim. The fixture holds every shape
// the claims need; the subtests read the one SBOM.
//
// scan root
//
//	loose.txt                          an ordinary file, counted by the file catalogers
//	nested/marker.txt                  excluded by the root-anchored pattern ./nested/marker.txt
//	app.zip                            nested/marker.txt, nested/keep.txt, nested/excluded.txt (**/excluded.txt)
//	app/data.zip                       nested/marker.txt, under a directory
//	outer.zip                          outer/marker.txt
//	  deeper/inner.zip                 nested/marker.txt, two levels down
//	  skip/inner-excluded.zip          nested/marker.txt, excluded by **/inner-excluded.zip
//	  日本語/café-🎉/unicode.zip          nested/marker.txt, under a non-ASCII path
//	pkg.rpm                            a zip holding a marker, excluded by **/*.rpm
//	KEPT.RPM                           the same zip, kept: the pattern is lower-case (a distinct base
//	                                   name, so the two coexist on a case-insensitive filesystem)
//	app.war                            WEB-INF/lib/war-lib-2.0.jar
//	bundle.zip                         lib/zip-lib-1.2.jar
//	bundle.tar.gz                      lib/tgz-lib-1.2.jar
var fixtureExclusions = []string{"./nested/marker.txt", "**/excluded.txt", "**/inner-excluded.zip", "**/*.rpm"}

func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	marker := map[string]string{"nested/marker.txt": "hello"}
	markerZip := buildZipBytes(t, marker)

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "nested"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "app"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "loose.txt"), []byte("outside"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nested", "marker.txt"), []byte("at the root"), 0o644))

	writeTestZip(t, filepath.Join(dir, "app.zip"), map[string]string{
		"nested/marker.txt":   "hello",
		"nested/keep.txt":     "hello",
		"nested/excluded.txt": "hello",
	})
	writeTestZipRaw(t, filepath.Join(dir, "app", "data.zip"), map[string][]byte{"nested/marker.txt": []byte("hello")})
	writeTestZipRaw(t, filepath.Join(dir, "outer.zip"), map[string][]byte{
		"outer/marker.txt":        []byte("hello"),
		"deeper/inner.zip":        markerZip,
		"skip/inner-excluded.zip": markerZip,
		"日本語/café-🎉/unicode.zip":  markerZip,
	})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pkg.rpm"), markerZip, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "KEPT.RPM"), markerZip, 0o644))

	writeTestZipRaw(t, filepath.Join(dir, "app.war"), map[string][]byte{
		"WEB-INF/lib/war-lib-2.0.jar": jarBytes(t, "war-lib", "2.0"),
	})
	writeTestZipRaw(t, filepath.Join(dir, "bundle.zip"), map[string][]byte{
		"lib/zip-lib-1.2.jar": jarBytes(t, "zip-lib", "1.2"),
	})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bundle.tar.gz"), buildTarGzBytes(t, map[string][]byte{
		"lib/tgz-lib-1.2.jar": jarBytes(t, "tgz-lib", "1.2"),
	}), 0o644))
	return dir
}

func TestArchiveCataloger(t *testing.T) {
	scanDir := writeFixture(t)
	resolvedScanDir, err := filepath.EvalSymlinks(scanDir)
	require.NoError(t, err)

	recorder := &recordingBus{}
	bus.Set(recorder)
	t.Cleanup(func() { bus.Set(nil) })

	var (
		probeMu sync.Mutex
		seen    []string // every .txt and .zip path any resolver handed a cataloger could see
	)
	probe := resolverProbeCataloger{globs: []string{"**/*.txt", "**/*.zip"}, record: func(paths []string) {
		probeMu.Lock()
		defer probeMu.Unlock()
		seen = append(seen, paths...)
	}}

	// the java catalogers come from the factory, as the CLI builds them: the flag handing recursion
	// to the archive task is derived onto the factory's config. Both legacy search settings are off,
	// the cell of the matrix that looks like a bug: with the feature on they no longer gate anything
	packages := pkgcataloging.DefaultConfig()
	packages.JavaArchive.IncludeIndexedArchives = false
	packages.JavaArchive.IncludeUnindexedArchives = false
	cfg := DefaultCreateSBOMConfig().
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults("java")).
		WithCatalogers(
			pkgcataloging.NewAlwaysEnabledCatalogerReference(markerCataloger{}),
			pkgcataloging.NewAlwaysEnabledCatalogerReference(probe),
		).
		WithPackagesConfig(packages).
		WithFilesConfig(filecataloging.DefaultConfig().WithSelection(file.AllFilesSelection)).
		WithArchiveConfig(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(3))

	s := scanDirWithExclusions(t, scanDir, cfg, fixtureExclusions...)

	t.Run("markers are found at every depth under archive-relative paths", func(t *testing.T) {
		// the location's ArchivePath is the chain of archives; RealPath is relative to the innermost
		assert.Equal(t, []string{
			"KEPT.RPM|nested/marker.txt",
			"app.zip|nested/marker.txt",
			"app/data.zip|nested/marker.txt",
			"outer.zip:deeper/inner.zip|nested/marker.txt",
			"outer.zip:日本語/café-🎉/unicode.zip|nested/marker.txt",
			"outer.zip|outer/marker.txt",
		}, packageLocations(s, "marker-pkg"))
	})

	t.Run("archive contents do not leak into the parent tree", func(t *testing.T) {
		for _, loc := range packageLocations(s, "marker-pkg") {
			assert.NotContains(t, loc, ".zip/", "a joined path smears the archive's contents into the parent's tree")
			assert.NotContains(t, loc, "|/", "a nested path must not be rooted")
		}
	})

	t.Run("unicode entry names survive to output", func(t *testing.T) {
		for _, loc := range packageLocations(s, "marker-pkg") {
			assert.True(t, utf8.ValidString(loc))
		}
	})

	t.Run("a CONTAINS relationship links each archive to what was found inside", func(t *testing.T) {
		var containers []string
		for _, p := range s.Artifacts.Packages.Sorted() {
			if p.Name != "marker-pkg" {
				continue
			}
			for _, rel := range s.Relationships {
				if rel.Type != artifact.ContainsRelationship || rel.To.ID() != p.ID() {
					continue
				}
				if coords, ok := rel.From.(file.Coordinates); ok {
					containers = append(containers, coords.ArchivePath+"|"+coords.RealPath)
				}
			}
		}
		sort.Strings(containers)
		assert.Equal(t, []string{
			"outer.zip|deeper/inner.zip",
			"outer.zip|日本語/café-🎉/unicode.zip",
			"|KEPT.RPM",
			"|app.zip",
			"|app/data.zip",
			"|outer.zip",
		}, containers, "the archive file, named in its own parent, contains the package")
	})

	t.Run("exclusions are the scan's own", func(t *testing.T) {
		// there is no archive-specific exclusion setting: a scan pattern's shape decides whether it
		// reaches inside an archive, and an excluded entry is absent from the archive's filesystem
		// rather than present and skipped
		markers := packageLocations(s, "marker-pkg")
		assert.NotContains(t, markers, "|nested/marker.txt", "a root-anchored pattern excludes the file at the scan root")
		assert.Contains(t, markers, "app.zip|nested/marker.txt", "and says nothing about the same path inside an archive")
		assert.NotContains(t, markers, "pkg.rpm|nested/marker.txt", "an archive whose own path is excluded is not extracted")
		assert.Contains(t, markers, "KEPT.RPM|nested/marker.txt", "a lower-case pattern does not match an upper-case name")
		assert.NotContains(t, markers, "outer.zip:skip/inner-excluded.zip|nested/marker.txt", "a nested archive is excluded at its own level")

		assert.Contains(t, seen, "nested/keep.txt")
		assert.NotContains(t, seen, "nested/excluded.txt", "a **/ pattern excludes inside an archive, from the index itself")
		assert.Contains(t, seen, "deeper/inner.zip", "the probe ran inside outer.zip")
		assert.NotContains(t, seen, "skip/inner-excluded.zip", "the excluded inner archive is absent from outer's filesystem")
	})

	t.Run("a jar inside an archive is cataloged exactly once, under the virtual path java gives it", func(t *testing.T) {
		// the failure mode is a duplicate: a jar inside a zip can be reached by the task's walk and by
		// the java cataloger's own unarchiving. The colon-delimited virtual path appears in published
		// SBOMs, so it must not change with the mechanism; for a directory source the archive's path
		// is relative, so the chain has no leading separator
		assert.Equal(t, map[string][]string{
			"war-lib": {"app.war:WEB-INF/lib/war-lib-2.0.jar"},
			"zip-lib": {"bundle.zip:lib/zip-lib-1.2.jar"},
			"tgz-lib": {"bundle.tar.gz:lib/tgz-lib-1.2.jar"},
		}, javaVirtualPaths(s), "with both legacy search settings off, every container is still descended")
	})

	t.Run("no extraction path reaches the SBOM", func(t *testing.T) {
		// covers syft/archive-content-identity#nested-paths-are-archive-relative: file cataloging is
		// the one path that enumerates every location rather than searching for them, so a resolver
		// root that leaked would land in FileMetadata and gain a CONTAINS edge
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
			assert.NotContains(t, p, "archive-spill-", "the spill file reached the SBOM at %q", p)
			if filepath.IsAbs(p) {
				// the directory resolver has always reported the scan root absolute: it is the path the
				// user asked for. Anything else absolute is a filesystem this feature invented
				assert.Equal(t, resolvedScanDir, p, "only the scanned directory itself may be reported absolute")
			}
		}
	})

	t.Run("file metadata covers every entry of every archive, and nothing else", func(t *testing.T) {
		// an exact set is also the reproducibility check: anything of a per-run temp directory reaching
		// output would fail it
		var got []string
		for coords := range s.Artifacts.FileMetadata {
			if coords.ArchivePath == "" {
				continue
			}
			got = append(got, coords.ArchivePath+"|"+coords.RealPath)
		}
		sort.Strings(got)
		assert.Equal(t, []string{
			"KEPT.RPM|nested/marker.txt",
			"app.war:WEB-INF/lib/war-lib-2.0.jar|META-INF/MANIFEST.MF",
			"app.war|WEB-INF/lib/war-lib-2.0.jar",
			"app.zip|nested/keep.txt",
			"app.zip|nested/marker.txt",
			"app/data.zip|nested/marker.txt",
			"bundle.tar.gz:lib/tgz-lib-1.2.jar|META-INF/MANIFEST.MF",
			"bundle.tar.gz|lib/tgz-lib-1.2.jar",
			"bundle.zip:lib/zip-lib-1.2.jar|META-INF/MANIFEST.MF",
			"bundle.zip|lib/zip-lib-1.2.jar",
			"outer.zip:deeper/inner.zip|nested/marker.txt",
			"outer.zip:日本語/café-🎉/unicode.zip|nested/marker.txt",
			"outer.zip|deeper/inner.zip",
			"outer.zip|outer/marker.txt",
			"outer.zip|日本語/café-🎉/unicode.zip",
		}, got)
	})

	t.Run("file catalogers publish one progress row counting archive contents", func(t *testing.T) {
		// the file catalogers run once over the scan root and again over every archive; each must
		// report into one row carrying the total of every run, or the count runs past the total and
		// renders as an overshot bar that reads as complete mid-walk
		rows := map[string][]*progress.Manual{}
		for _, e := range recorder.events {
			if e.Type != event.CatalogerTaskStarted {
				continue
			}
			info, ok := e.Source.(monitor.GenericTask)
			require.True(t, ok)
			tp, ok := e.Value.(*monitor.TaskProgress)
			require.True(t, ok)
			rows[info.Title.Default] = append(rows[info.Title.Default], tp.Manual)
		}
		for _, title := range []string{"File digests", "File metadata"} {
			published := rows[title]
			require.Len(t, published, 1, "%s must publish exactly one row for the whole scan", title)
			row := published[0]
			assert.Greater(t, row.Current(), int64(len(s.Artifacts.FileMetadata))/2,
				"%s must count the files inside the archives, got %d", title, row.Current())
			if row.Size() >= 0 {
				assert.Equal(t, row.Current(), row.Size(), "%s total must cover every run that reported into it", title)
			}
		}
	})
}

// TestArchiveCataloger_featureOff is the one comparison that needs a second scan: with the task
// disabled, java's own unarchiving reaches the jars its legacy settings admit, under the same virtual
// path the task gives them.
func TestArchiveCataloger_featureOff(t *testing.T) {
	scanDir := writeFixture(t)

	cfg := DefaultCreateSBOMConfig().
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults("java"))

	s := scanDirWithExclusions(t, scanDir, cfg, fixtureExclusions...)

	// indexed archives (zip, war) are searched by default and unindexed ones (tar.gz) are not, so
	// what a user gets without the feature depends on settings the feature makes irrelevant
	assert.Equal(t, map[string][]string{
		"war-lib": {"app.war:WEB-INF/lib/war-lib-2.0.jar"},
		"zip-lib": {"bundle.zip:lib/zip-lib-1.2.jar"},
	}, javaVirtualPaths(s), "java's own recursion finds each once, under the virtual path the task also reports")

	t.Run("the top-level archive search booleans reach java", func(t *testing.T) {
		cfg := DefaultCreateSBOMConfig().
			WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults("java")).
			WithArchiveConfig(cataloging.DefaultArchiveSearchConfig().WithIncludeUnindexedArchives(true))

		s := scanDirWithExclusions(t, scanDir, cfg, fixtureExclusions...)

		assert.Contains(t, javaVirtualPaths(s), "tgz-lib")
		assert.False(t, cfg.Packages.JavaArchive.IncludeUnindexedArchives, "the caller's config is not written to")
	})
}

func TestArchiveCataloger_jarReachedThroughALinkIsIdentified(t *testing.T) {
	// a content-addressed layout (pnpm, nix, bazel): the jar is stored under a hash and only the link
	// to it is named like a jar
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	jar := jarBytes(t, "json-simple", "1.1.1")
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "store/3f9a1c", Mode: 0o644, Size: int64(len(jar))}))
	_, err := tw.Write(jar)
	require.NoError(t, err)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "app/lib/json-simple-1.1.1.jar", Typeflag: tar.TypeSymlink, Linkname: "../../store/3f9a1c"}))
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bundle.tar.gz"), buf.Bytes(), 0o644))

	cfg := DefaultCreateSBOMConfig().
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults("java")).
		WithArchiveConfig(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(2))
	s := scanDirWithExclusions(t, dir, cfg)

	assert.Equal(t, []string{"bundle.tar.gz|store/3f9a1c"}, packageLocations(s, "json-simple"))
}

func TestArchiveCataloger_descriptorRecordsArchiveConfig(t *testing.T) {
	// a consumer must be able to tell from the SBOM alone how deep archive contents were searched
	cfg := DefaultCreateSBOMConfig().
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults("java")).
		WithArchiveConfig(cataloging.DefaultArchiveSearchConfig().WithMaxDepth(3))
	s := scanDirWithExclusions(t, t.TempDir(), cfg)

	trail, ok := s.Descriptor.Configuration.(configurationAuditTrail)
	require.True(t, ok)
	assert.Equal(t, 3, trail.Archive.MaxDepth)
	assert.Contains(t, trail.Catalogers.Used, task.ArchiveCatalogerTaskName)
}

func TestArchiveCataloger_javaArchiveDepthIsAConfigError(t *testing.T) {
	// depth and limits are not java settings; setting them on java's deprecated copy must fail fast
	// rather than be silently ignored
	for name, set := range map[string]func(*cataloging.ArchiveSearchConfig){
		"max depth":        func(c *cataloging.ArchiveSearchConfig) { c.MaxDepth = 3 },
		"max memory bytes": func(c *cataloging.ArchiveSearchConfig) { c.MaxMemoryBytes = 1 },
		"max disk bytes":   func(c *cataloging.ArchiveSearchConfig) { c.MaxDiskBytes = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			supplied := java.DefaultArchiveCatalogerConfig()
			supplied.ArchiveSearchConfig = cataloging.ArchiveSearchConfig{}
			set(&supplied.ArchiveSearchConfig)
			cfg := DefaultCreateSBOMConfig().WithPackagesConfig(pkgcataloging.Config{JavaArchive: supplied})

			src, err := directorysource.New(directorysource.Config{Path: t.TempDir()})
			require.NoError(t, err)
			t.Cleanup(func() { _ = src.Close() })

			_, err = cfg.Create(context.Background(), src)
			require.ErrorContains(t, err, "set them with CreateSBOMConfig.Archive")
		})
	}
}

// packageLocations lists "archivePath|realPath" for every location of every package with the name.
func packageLocations(s *sbom.SBOM, name string) []string {
	var out []string
	for _, p := range s.Artifacts.Packages.Sorted() {
		if p.Name != name {
			continue
		}
		for _, loc := range p.Locations.ToSlice() {
			out = append(out, loc.ArchivePath+"|"+loc.RealPath)
		}
	}
	sort.Strings(out)
	return out
}

// javaVirtualPaths maps each java package name to the virtual paths it was reported under; a name
// with two entries was cataloged twice.
func javaVirtualPaths(s *sbom.SBOM) map[string][]string {
	out := map[string][]string{}
	for _, p := range s.Artifacts.Packages.Sorted() {
		if metadata, ok := p.Metadata.(pkg.JavaArchive); ok {
			out[p.Name] = append(out[p.Name], metadata.VirtualPath)
		}
	}
	return out
}

// markerCataloger is a stub package cataloger emitting one package per "marker.txt" it finds, so the
// end-to-end tests assert behavior without depending on any real cataloger's fixture format.
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

// resolverProbeCataloger reports what the resolver it was handed can see, which is how "absent from
// the index" is told from "present and skipped" within a scan.
type resolverProbeCataloger struct {
	globs  []string
	record func([]string)
}

func (resolverProbeCataloger) Name() string { return "resolver-probe-cataloger" }

func (c resolverProbeCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	locations, err := resolver.FilesByGlob(c.globs...)
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

// recordingBus captures the progress rows a scan publishes.
type recordingBus struct {
	mu     sync.Mutex
	events []partybus.Event
}

func (p *recordingBus) Publish(e partybus.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, e)
}

// scanDirWithExclusions scans with the given exclusion patterns configured on the source, where
// exclusions live; archive cataloging has no exclusion setting of its own.
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

func writeTestZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, buildZipBytes(t, files), 0o644))
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

// buildZipBytesRaw writes entries in sorted name order rather than map order: limits are enforced as
// the walk proceeds, so entry order decides which entries land before a truncation.
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

func buildTarGzBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, name := range names {
		body := files[name]
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}))
		_, err := tw.Write(body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

// jarBytes is the smallest jar the java cataloger identifies: a manifest naming the artifact.
func jarBytes(t *testing.T, title, version string) []byte {
	t.Helper()
	return buildZipBytesRaw(t, map[string][]byte{
		"META-INF/MANIFEST.MF": []byte(
			"Manifest-Version: 1.0\nImplementation-Title: " + title + "\nImplementation-Version: " + version + "\n",
		),
	})
}

package java

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

// Test_virtualPathFromArchiveTraversal_colonInEntryPath is the java-cataloger-level counterpart of
// internal/archive's escaping tests: a package reached through an entry whose path contains a colon
// must carry it escaped as %3A end to end in its virtual path, while the maven-derived
// ":groupID:artifactID" suffix that distinguishes a pom.properties package from its containing archive
// is still appended with real, unescaped delimiters.
func Test_virtualPathFromArchiveLocation_colonInEntryPath(t *testing.T) {
	jarBytes := makeTestZip(t, map[string][]byte{
		"META-INF/MANIFEST.MF": testManifest("outer-app", "1.0.0"),
		"META-INF/maven/com.example/different-lib/pom.properties": []byte(
			"groupId=com.example\nartifactId=different-lib\nversion=9.9.9\n",
		),
	})

	// as the archive cataloger task's resolver would present an entry of outer.zip
	location := file.NewLocation("/lib/dep:special.jar")
	location.ArchivePath = "outer.zip"

	gap := newGenericArchiveParserAdapter(ArchiveCatalogerConfig{})
	pkgs, _, err := gap.processJavaArchive(pkgtest.Context(t), file.LocationReadCloser{
		Location:   location,
		ReadCloser: io.NopCloser(bytes.NewReader(jarBytes)),
	}, nil)
	require.NoError(t, err)
	require.Len(t, pkgs, 2)

	var mainPkg, auxPkg *pkg.Package
	for i := range pkgs {
		if pkgs[i].Name == "outer-app" {
			mainPkg = &pkgs[i]
		} else if pkgs[i].Name == "different-lib" {
			auxPkg = &pkgs[i]
		}
	}
	require.NotNil(t, mainPkg, "expected a package from the manifest")
	require.NotNil(t, auxPkg, "expected a package from pom.properties")

	mainMetadata, ok := mainPkg.Metadata.(pkg.JavaArchive)
	require.True(t, ok)
	assert.Equal(t, "outer.zip:lib/dep%3Aspecial.jar", mainMetadata.VirtualPath,
		"the entry's own colon must be escaped, and it is the only delimiter in play here")

	auxMetadata, ok := auxPkg.Metadata.(pkg.JavaArchive)
	require.True(t, ok)
	assert.Equal(t, "outer.zip:lib/dep%3Aspecial.jar:com.example:different-lib", auxMetadata.VirtualPath,
		"the maven groupID:artifactID suffix is appended with real, unescaped delimiters")
}

func Test_nestedArchiveOwnershipSwitch(t *testing.T) {
	nestedJar := makeTestZip(t, map[string][]byte{
		"META-INF/MANIFEST.MF": testManifest("nested-lib", "2.0"),
	})
	outerJar := makeTestZip(t, map[string][]byte{
		"META-INF/MANIFEST.MF":   testManifest("example-app", "1.0.0"),
		"lib/nested-lib-2.0.jar": nestedJar,
	})

	parse := func(t *testing.T, ctx context.Context, cfg ArchiveCatalogerConfig) []pkg.Package {
		gap := newGenericArchiveParserAdapter(cfg)
		pkgs, _, err := gap.processJavaArchive(ctx, file.LocationReadCloser{
			Location:   file.NewLocation("example-app-1.0.0.jar"),
			ReadCloser: io.NopCloser(bytes.NewReader(outerJar)),
		}, nil)
		require.NoError(t, err)
		return pkgs
	}

	t.Run("nested archive cataloging disabled: this cataloger unarchives nested jars itself", func(t *testing.T) {
		pkgs := parse(t, pkgtest.Context(t), DefaultArchiveCatalogerConfig()) // MaxDepth defaults to 0 (disabled)
		require.Len(t, pkgs, 2)

		var names, virtualPaths []string
		for _, p := range pkgs {
			names = append(names, p.Name)
			metadata, ok := p.Metadata.(pkg.JavaArchive)
			require.True(t, ok)
			virtualPaths = append(virtualPaths, metadata.VirtualPath)
		}
		assert.ElementsMatch(t, []string{"example-app", "nested-lib"}, names)
		assert.ElementsMatch(t, []string{
			"example-app-1.0.0.jar",
			"example-app-1.0.0.jar:lib/nested-lib-2.0.jar",
		}, virtualPaths)
	})

	t.Run("nested archive cataloging enabled: this cataloger does not unarchive", func(t *testing.T) {
		// only syft.CreateSBOM marks the context in production; it is not reachable from user config
		ctx := archive.WithNestedCataloging(pkgtest.Context(t))

		// no error expected: the nested jar is deliberately left to the archive cataloger task
		pkgs := parse(t, ctx, DefaultArchiveCatalogerConfig())
		require.Len(t, pkgs, 1)
		assert.Equal(t, "example-app", pkgs[0].Name)
	})

	t.Run("java's own archive-search depth does not hand off recursion", func(t *testing.T) {
		// a library consumer setting java's squash-inlined MaxDepth must neither enable nor disable
		// nested archive cataloging: that knob is Archive.MaxDepth on CreateSBOMConfig. Getting it
		// wrong silently drops nested jars for every consumer that is not the CLI.
		cfg := DefaultArchiveCatalogerConfig()
		cfg.ArchiveSearchConfig = cfg.ArchiveSearchConfig.WithMaxDepth(2)

		pkgs := parse(t, pkgtest.Context(t), cfg)
		require.Len(t, pkgs, 2, "this cataloger must still recurse itself")
	})
}

func Test_NewArchiveCataloger_wrappedParserRegistration(t *testing.T) {
	// the wrapped-archive parsers exist only because the archive cataloger did not. When it is enabled
	// it extracts zip and tar containers itself and this cataloger meets the same jars one nesting level
	// down, so registering them would double the work.
	//
	// Asserted through the globs the cataloger queries, the observable consequence of a registration.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "placeholder.txt"), []byte("x"), 0o600))

	queriedGlobs := func(t *testing.T, ctx context.Context, cfg ArchiveCatalogerConfig) *pkgtest.ObservingResolver {
		t.Helper()
		src, err := directorysource.NewFromPath(dir)
		require.NoError(t, err)
		resolver, err := src.FileResolver(source.AllLayersScope)
		require.NoError(t, err)

		observed := pkgtest.NewObservingResolver(resolver)
		_, _, err = NewArchiveCataloger(cfg).Catalog(ctx, observed)
		require.NoError(t, err)
		return observed
	}

	t.Run("wrapped parsers are not registered when the archive cataloger owns recursion", func(t *testing.T) {
		cfg := DefaultArchiveCatalogerConfig()
		cfg.IncludeIndexedArchives = true
		cfg.IncludeUnindexedArchives = true

		observed := queriedGlobs(t, archive.WithNestedCataloging(pkgtest.Context(t)), cfg)
		// outside a traversal the cataloger opens no files at all: the task brings every archive back
		// as an extracted filesystem, and each is described there
		assert.False(t, observed.ObservedPathQuery("**/*.zip"), "no generic zip parser may be registered")
		assert.False(t, observed.ObservedPathQuery("**/*.tar"), "no generic tar parser may be registered")
		assert.False(t, observed.ObservedPathQuery("**/*.jar"), "archive files are the task's to open")
	})

	t.Run("wrapped parsers stay registered when the feature is off", func(t *testing.T) {
		cfg := DefaultArchiveCatalogerConfig()
		cfg.IncludeIndexedArchives = true
		cfg.IncludeUnindexedArchives = true

		observed := queriedGlobs(t, pkgtest.Context(t), cfg)
		assert.True(t, observed.ObservedPathQuery("**/*.zip"), "existing behavior must be unchanged")
		assert.True(t, observed.ObservedPathQuery("**/*.tar"), "existing behavior must be unchanged")
	})

	t.Run("the existing include settings still gate them when the feature is off", func(t *testing.T) {
		cfg := DefaultArchiveCatalogerConfig()
		cfg.IncludeIndexedArchives = false
		cfg.IncludeUnindexedArchives = false

		observed := queriedGlobs(t, pkgtest.Context(t), cfg)
		assert.False(t, observed.ObservedPathQuery("**/*.zip"))
		assert.False(t, observed.ObservedPathQuery("**/*.tar"))
	})
}

func Test_mavenVirtualPathSuffixUnderTraversal(t *testing.T) {
	// a package derived from a pom.properties whose artifact does not match the containing archive gets
	// a trailing ":<groupID>:<artifactID>" appended to the archive's virtual path. That suffix form is in
	// published SBOMs, and once the archive cataloger drives the parser the base carries the location's
	// archive path - so the two must compose rather than one clobbering the other.
	jarBytes := makeTestZip(t, map[string][]byte{
		"META-INF/MANIFEST.MF": testManifest("example-app", "1.0.0"),
		"META-INF/maven/com.example.other/other-lib/pom.properties": []byte(
			"groupId=com.example.other\nartifactId=other-lib\nversion=2.5.0\n",
		),
	})

	parse := func(t *testing.T, archivePath, readerPath string) []pkg.Package {
		t.Helper()
		location := file.NewLocation(readerPath)
		location.ArchivePath = archivePath
		gap := newGenericArchiveParserAdapter(ArchiveCatalogerConfig{})
		pkgs, _, err := gap.processJavaArchive(pkgtest.Context(t), file.LocationReadCloser{
			Location:   location,
			ReadCloser: io.NopCloser(bytes.NewReader(jarBytes)),
		}, nil)
		require.NoError(t, err)
		return pkgs
	}

	virtualPathOf := func(t *testing.T, pkgs []pkg.Package, name string) string {
		t.Helper()
		for _, p := range pkgs {
			if p.Name != name {
				continue
			}
			metadata, ok := p.Metadata.(pkg.JavaArchive)
			require.True(t, ok)
			return metadata.VirtualPath
		}
		t.Fatalf("no package named %q in %v", name, pkgs)
		return ""
	}

	t.Run("outside an archive: suffix hangs off the reader path", func(t *testing.T) {
		pkgs := parse(t, "", "/example-app-1.0.0.jar")
		assert.Equal(t, "/example-app-1.0.0.jar:com.example.other:other-lib",
			virtualPathOf(t, pkgs, "other-lib"))
	})

	t.Run("inside an archive: suffix hangs off the archive chain", func(t *testing.T) {
		pkgs := parse(t, "app.war", "/WEB-INF/lib/example-app-1.0.0.jar")
		assert.Equal(t, "app.war:WEB-INF/lib/example-app-1.0.0.jar:com.example.other:other-lib",
			virtualPathOf(t, pkgs, "other-lib"))
	})
}

// makeTestZip builds a zip in memory so the parser can be exercised without the java-toolchain-built
// fixtures.
func makeTestZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write(content)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func testManifest(title, version string) []byte {
	return fmt.Appendf(nil, "Manifest-Version: 1.0\nImplementation-Title: %s\nImplementation-Version: %s\n", title, version)
}

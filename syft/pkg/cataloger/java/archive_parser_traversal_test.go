package java

import (
	"archive/zip"
	"bytes"
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

// makeTestZip builds a zip in memory so the parser can be exercised without the
// java-toolchain-built fixtures.
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

func Test_virtualPathFromArchiveTraversal(t *testing.T) {
	jarBytes := makeTestZip(t, map[string][]byte{
		"META-INF/MANIFEST.MF": testManifest("example-app", "1.0.0"),
	})

	parse := func(t *testing.T, traversal *archive.Traversal, readerPath string) pkg.Package {
		ctx := pkgtest.Context(t)
		if traversal != nil {
			ctx = archive.WithTraversal(ctx, traversal)
		}
		gap := newGenericArchiveParserAdapter(ArchiveCatalogerConfig{})
		pkgs, _, err := gap.processJavaArchive(ctx, file.LocationReadCloser{
			Location:   file.NewLocation(readerPath),
			ReadCloser: io.NopCloser(bytes.NewReader(jarBytes)),
		}, nil)
		require.NoError(t, err)
		require.Len(t, pkgs, 1)
		return pkgs[0]
	}

	t.Run("no traversal keeps reader path as virtual path", func(t *testing.T) {
		p := parse(t, nil, "some/dir/example-app-1.0.0.jar")
		metadata, ok := p.Metadata.(pkg.JavaArchive)
		require.True(t, ok)
		assert.Equal(t, "some/dir/example-app-1.0.0.jar", metadata.VirtualPath)
		assert.Equal(t, "example-app", p.Name)
		assert.Equal(t, "1.0.0", p.Version)
	})

	t.Run("traversal prepends containing archive chain", func(t *testing.T) {
		trav := &archive.Traversal{
			Location:     file.NewLocation("/app.war"),
			VirtualPath:  "/app.war",
			FileSystemID: "app.war",
			Depth:        1,
		}
		p := parse(t, trav, "/WEB-INF/lib/example-app-1.0.0.jar")
		metadata, ok := p.Metadata.(pkg.JavaArchive)
		require.True(t, ok)
		assert.Equal(t, "/app.war:WEB-INF/lib/example-app-1.0.0.jar", metadata.VirtualPath)
		// name/version inference from the last virtual path element is unaffected by the chain
		assert.Equal(t, "example-app", p.Name)
		assert.Equal(t, "1.0.0", p.Version)
	})

	t.Run("multi-level traversal chains all parents", func(t *testing.T) {
		outer := &archive.Traversal{VirtualPath: "/dist.zip", FileSystemID: "dist.zip", Depth: 1}
		inner := &archive.Traversal{
			VirtualPath:  outer.VirtualPathOf("/app.war"),
			FileSystemID: "dist.zip/app.war",
			Depth:        2,
			Parent:       outer,
		}
		p := parse(t, inner, "/WEB-INF/lib/example-app-1.0.0.jar")
		metadata, ok := p.Metadata.(pkg.JavaArchive)
		require.True(t, ok)
		assert.Equal(t, "/dist.zip:app.war:WEB-INF/lib/example-app-1.0.0.jar", metadata.VirtualPath)
	})
}

// Test_virtualPathFromArchiveTraversal_colonInEntryPath is the java-cataloger-level counterpart
// of internal/archive's escaping tests: a package reached through an entry whose own path
// contains a colon must carry that colon escaped as %3A end to end in its virtual path
// (decisions.md#colon-in-an-entry-path-is-escaped), and the maven-derived
// ":groupID:artifactID" suffix that distinguishes a pom.properties package from its containing
// archive must still be appended using real, unescaped delimiters.
func Test_virtualPathFromArchiveTraversal_colonInEntryPath(t *testing.T) {
	jarBytes := makeTestZip(t, map[string][]byte{
		"META-INF/MANIFEST.MF": testManifest("outer-app", "1.0.0"),
		"META-INF/maven/com.example/different-lib/pom.properties": []byte(
			"groupId=com.example\nartifactId=different-lib\nversion=9.9.9\n",
		),
	})

	trav := &archive.Traversal{
		Location:     file.NewLocation("/outer.zip"),
		VirtualPath:  "outer.zip",
		FileSystemID: "outer.zip",
		Depth:        1,
	}
	ctx := archive.WithTraversal(pkgtest.Context(t), trav)

	gap := newGenericArchiveParserAdapter(ArchiveCatalogerConfig{})
	pkgs, _, err := gap.processJavaArchive(ctx, file.LocationReadCloser{
		Location:   file.NewLocation("/lib/dep:special.jar"),
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

	parse := func(t *testing.T, cfg ArchiveCatalogerConfig) []pkg.Package {
		gap := newGenericArchiveParserAdapter(cfg)
		pkgs, _, err := gap.processJavaArchive(pkgtest.Context(t), file.LocationReadCloser{
			Location:   file.NewLocation("example-app-1.0.0.jar"),
			ReadCloser: io.NopCloser(bytes.NewReader(outerJar)),
		}, nil)
		require.NoError(t, err)
		return pkgs
	}

	t.Run("nested archive cataloging disabled: this cataloger unarchives nested jars itself", func(t *testing.T) {
		pkgs := parse(t, DefaultArchiveCatalogerConfig()) // MaxDepth defaults to 0 (disabled)
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
		cfg := DefaultArchiveCatalogerConfig()
		// only CreateSBOMConfig sets this in production; it is not reachable from user config
		cfg.NestedArchivesHandledExternally = true

		// no error expected: the nested jar is deliberately left to the archive cataloger task
		pkgs := parse(t, cfg)
		require.Len(t, pkgs, 1)
		assert.Equal(t, "example-app", pkgs[0].Name)
	})

	t.Run("java's own archive-search depth does not hand off recursion", func(t *testing.T) {
		// a library consumer setting java's squash-inlined MaxDepth must neither enable nor
		// disable nested archive cataloging: that knob is Archive.MaxDepth on CreateSBOMConfig.
		// Getting this wrong silently drops nested jars for every consumer that is not the CLI.
		cfg := DefaultArchiveCatalogerConfig()
		cfg.ArchiveSearchConfig = cfg.ArchiveSearchConfig.WithMaxDepth(2)
		require.False(t, cfg.nestedArchivesHandledExternally())

		pkgs := parse(t, cfg)
		require.Len(t, pkgs, 2, "this cataloger must still recurse itself")
	})
}

func Test_NewArchiveCataloger_wrappedParserRegistration(t *testing.T) {
	// the wrapped-archive parsers exist only because the generic archive cataloger did not. When it
	// is enabled it extracts zip and tar containers itself and this cataloger meets the same JARs
	// one nesting level down, so registering them would double the work.
	//
	// asserted through the globs the cataloger actually queries, since that is the observable
	// consequence of a parser being registered
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "placeholder.txt"), []byte("x"), 0o600))

	queriedGlobs := func(t *testing.T, cfg ArchiveCatalogerConfig) *pkgtest.ObservingResolver {
		t.Helper()
		src, err := directorysource.NewFromPath(dir)
		require.NoError(t, err)
		resolver, err := src.FileResolver(source.AllLayersScope)
		require.NoError(t, err)

		observed := pkgtest.NewObservingResolver(resolver)
		_, _, err = NewArchiveCataloger(cfg).Catalog(pkgtest.Context(t), observed)
		require.NoError(t, err)
		return observed
	}

	t.Run("wrapped parsers are not registered when the archive cataloger owns recursion", func(t *testing.T) {
		cfg := DefaultArchiveCatalogerConfig()
		cfg.IncludeIndexedArchives = true
		cfg.IncludeUnindexedArchives = true
		cfg.NestedArchivesHandledExternally = true

		observed := queriedGlobs(t, cfg)
		assert.False(t, observed.ObservedPathQuery("**/*.zip"), "no generic zip parser may be registered")
		assert.False(t, observed.ObservedPathQuery("**/*.tar"), "no generic tar parser may be registered")

		// the JAR-family globs are still registered: this cataloger is still the java parser
		assert.True(t, observed.ObservedPathQuery("**/*.jar"))
	})

	t.Run("wrapped parsers stay registered when the feature is off", func(t *testing.T) {
		cfg := DefaultArchiveCatalogerConfig()
		cfg.IncludeIndexedArchives = true
		cfg.IncludeUnindexedArchives = true

		observed := queriedGlobs(t, cfg)
		assert.True(t, observed.ObservedPathQuery("**/*.zip"), "existing behavior must be unchanged")
		assert.True(t, observed.ObservedPathQuery("**/*.tar"), "existing behavior must be unchanged")
	})

	t.Run("the existing include settings still gate them when the feature is off", func(t *testing.T) {
		cfg := DefaultArchiveCatalogerConfig()
		cfg.IncludeIndexedArchives = false
		cfg.IncludeUnindexedArchives = false

		observed := queriedGlobs(t, cfg)
		assert.False(t, observed.ObservedPathQuery("**/*.zip"))
		assert.False(t, observed.ObservedPathQuery("**/*.tar"))
	})
}

func Test_mavenVirtualPathSuffixUnderTraversal(t *testing.T) {
	// a package derived from a pom.properties whose artifact does not match the containing archive
	// gets a trailing ":<groupID>:<artifactID>" appended to the archive's virtual path. That suffix
	// form is in published SBOMs, and once the archive cataloger drives the parser the base it is
	// appended to comes from the traversal rather than from the reader path - so this asserts the
	// two compose rather than one clobbering the other.
	jarBytes := makeTestZip(t, map[string][]byte{
		"META-INF/MANIFEST.MF": testManifest("example-app", "1.0.0"),
		"META-INF/maven/com.example.other/other-lib/pom.properties": []byte(
			"groupId=com.example.other\nartifactId=other-lib\nversion=2.5.0\n",
		),
	})

	parse := func(t *testing.T, traversal *archive.Traversal, readerPath string) []pkg.Package {
		t.Helper()
		ctx := pkgtest.Context(t)
		if traversal != nil {
			ctx = archive.WithTraversal(ctx, traversal)
		}
		gap := newGenericArchiveParserAdapter(ArchiveCatalogerConfig{})
		pkgs, _, err := gap.processJavaArchive(ctx, file.LocationReadCloser{
			Location:   file.NewLocation(readerPath),
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

	t.Run("no traversal: suffix hangs off the reader path", func(t *testing.T) {
		pkgs := parse(t, nil, "/example-app-1.0.0.jar")
		assert.Equal(t, "/example-app-1.0.0.jar:com.example.other:other-lib",
			virtualPathOf(t, pkgs, "other-lib"))
	})

	t.Run("under traversal: suffix hangs off the archive chain", func(t *testing.T) {
		pkgs := parse(t, &archive.Traversal{VirtualPath: "app.war", Depth: 1}, "/WEB-INF/lib/example-app-1.0.0.jar")
		assert.Equal(t, "app.war:WEB-INF/lib/example-app-1.0.0.jar:com.example.other:other-lib",
			virtualPathOf(t, pkgs, "other-lib"))
	})
}

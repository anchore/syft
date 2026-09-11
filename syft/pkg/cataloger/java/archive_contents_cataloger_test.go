package java

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
)

// jarEntries is one java archive's worth of content, used both to build the archive the
// archive-reading cataloger parses and to lay out the filesystem the contents-reading one reads.
// The point of the pair of tests below is that these two must not disagree.
func jarEntries() map[string]string {
	return map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n" +
			"Implementation-Title: example-lib\n" +
			"Implementation-Version: 1.2.3\n",
		"META-INF/maven/com.example/example-lib/pom.properties": "groupId=com.example\n" +
			"artifactId=example-lib\nversion=1.2.3\n",
		"META-INF/maven/com.example/example-lib/pom.xml": `<project><modelVersion>4.0.0</modelVersion>
<groupId>com.example</groupId><artifactId>example-lib</artifactId><version>1.2.3</version>
<licenses><license><name>Apache License 2.0</name><url>https://www.apache.org/licenses/LICENSE-2.0</url></license></licenses>
</project>`,
		// a bundled dependency's maven metadata, which becomes a package of its own
		"META-INF/maven/com.other/bundled-dep/pom.properties": "groupId=com.other\n" +
			"artifactId=bundled-dep\nversion=4.5.6\n",
		"com/example/Thing.class": "not really bytecode",
	}
}

func writeJar(t *testing.T, dir, name string, entries map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.Create(n)
		require.NoError(t, err)
		_, err = w.Write([]byte(entries[n]))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())

	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, buf.Bytes(), 0o600))
	return p
}

// explode lays the same entries out as files, which is what the archive cataloger task hands the
// sub-pipeline once it has extracted an archive.
func explode(t *testing.T, dir string, entries map[string]string) {
	t.Helper()
	for name, contents := range entries {
		p := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(contents), 0o600))
	}
}

func summarize(pkgs []pkg.Package) []string {
	var out []string
	for _, p := range pkgs {
		meta, _ := p.Metadata.(pkg.JavaArchive)
		lics := p.Licenses.ToSlice()
		names := make([]string, 0, len(lics))
		for _, l := range lics {
			names = append(names, l.Value)
		}
		sort.Strings(names)
		out = append(out, p.Name+"@"+p.Version+" purl="+p.PURL+" vpath="+meta.VirtualPath+" lics="+
			joinSorted(names))
	}
	sort.Strings(out)
	return out
}

func joinSorted(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func Test_archiveContentsCataloger_agreesWithTheArchiveReadingCataloger(t *testing.T) {
	// the whole reason a second cataloger is tolerable: for the same archive it must report the same
	// packages, with the same identity, as the one that reads the archive file. Anything else is a
	// divergence that will be discovered as a diff in someone's SBOM.
	entries := jarEntries()
	cfg := DefaultArchiveCatalogerConfig()

	// the archive-reading cataloger, over a directory holding the jar
	archiveDir := t.TempDir()
	jarPath := writeJar(t, archiveDir, "example-lib-1.2.3.jar", entries)
	archiveResolver, err := fileresolver.NewFromDirectory(archiveDir, "")
	require.NoError(t, err)
	// the archive-reading cataloger copies the archive to a temp dir before it can read it, which is
	// the work the contents-reading one does not do
	archiveCtx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir()))
	fromArchive, _, err := NewArchiveCataloger(cfg).Catalog(archiveCtx, archiveResolver)
	require.NoError(t, err)
	require.NotEmpty(t, fromArchive)

	// the contents-reading cataloger, over the same entries laid out as a filesystem, with the
	// traversal the archive cataloger task would have placed on the context
	contentsDir := t.TempDir()
	explode(t, contentsDir, entries)
	contentsResolver, err := fileresolver.NewFromDirectory(contentsDir, "")
	require.NoError(t, err)

	// the traversal names the archive exactly as the resolver did for the archive-reading cataloger,
	// so both sides derive identity from the same string and the comparison is about the source of
	// the entries rather than about how the test spelled a path
	jarLocations, err := archiveResolver.FilesByGlob("**/*.jar")
	require.NoError(t, err)
	require.Len(t, jarLocations, 1)
	archivePath := jarLocations[0].Path()

	digests := digestsOfFile(t, jarPath)
	trav := &archive.Traversal{
		Location:     file.NewLocation(archivePath),
		VirtualPath:  archivePath,
		FileSystemID: "example-lib-1.2.3.jar",
		Depth:        1,
		Digests:      digests,
	}
	ctx := archive.WithTraversal(context.Background(), trav)
	fromContents, _, err := NewArchiveContentsCataloger(cfg).Catalog(ctx, contentsResolver)
	require.NoError(t, err)

	assert.Equal(t, summarize(fromArchive), summarize(fromContents))
}

func digestsOfFile(t *testing.T, path string) []file.Digest {
	t.Helper()
	entries, err := newZipEntries(context.Background(), path)
	require.NoError(t, err)
	digests, err := entries.digests(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, digests)
	return digests
}

func Test_archiveContentsCataloger_reportsNothingOutsideAnArchive(t *testing.T) {
	// no traversal means the scan is not inside an archive, and the identity of a java archive is
	// half in the file - so there is nothing this cataloger can say
	dir := t.TempDir()
	explode(t, dir, jarEntries())
	resolver, err := fileresolver.NewFromDirectory(dir, "")
	require.NoError(t, err)

	pkgs, _, err := NewArchiveContentsCataloger(DefaultArchiveCatalogerConfig()).
		Catalog(context.Background(), resolver)
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}

func Test_archiveContentsCataloger_reportsNothingForAnArchiveThatIsNotJava(t *testing.T) {
	// a .zip is an archive, and its contents are not a jar's contents. The archive-reading cataloger
	// draws that line with its globs; this one draws it with the same list.
	dir := t.TempDir()
	explode(t, dir, jarEntries())
	resolver, err := fileresolver.NewFromDirectory(dir, "")
	require.NoError(t, err)

	ctx := archive.WithTraversal(context.Background(), &archive.Traversal{
		Location:    file.NewLocation("/bundle.zip"),
		VirtualPath: "/bundle.zip",
		Depth:       1,
	})
	pkgs, _, err := NewArchiveContentsCataloger(DefaultArchiveCatalogerConfig()).Catalog(ctx, resolver)
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}

func Test_archiveContentsCataloger_noManifestIsNoPackage(t *testing.T) {
	// unchanged from the archive-reading cataloger, and worth asserting because it is the whole
	// coverage argument: a jar with no META-INF/MANIFEST.MF yields nothing today either, so requiring
	// the contents to be traversed takes away less than it appears to. Note the maven metadata here is
	// never consulted - without a main package there is nothing to attach it to.
	entries := map[string]string{
		"META-INF/maven/com.other/bundled-dep/pom.properties": "groupId=com.other\nartifactId=bundled-dep\nversion=4.5.6\n",
		"com/example/Thing.class":                             "not really bytecode",
	}

	dir := t.TempDir()
	explode(t, dir, entries)
	resolver, err := fileresolver.NewFromDirectory(dir, "")
	require.NoError(t, err)

	ctx := archive.WithTraversal(context.Background(), &archive.Traversal{
		Location:    file.NewLocation("no-manifest-1.0.0.jar"),
		VirtualPath: "no-manifest-1.0.0.jar",
		Depth:       1,
	})
	pkgs, _, err := NewArchiveContentsCataloger(DefaultArchiveCatalogerConfig()).Catalog(ctx, resolver)
	assert.Empty(t, pkgs)
	// reported against the archive rather than swallowed, and as an unknown rather than a scan failure
	require.Error(t, err)
	coordErrs, remaining := unknown.ExtractCoordinateErrors(err)
	assert.NoError(t, remaining)
	require.Len(t, coordErrs, 1)
	assert.Equal(t, "no-manifest-1.0.0.jar", coordErrs[0].Coordinates.RealPath)
}

func Test_archiveContentsCataloger_readsWhatWasExtractedAndNoMore(t *testing.T) {
	// the sharp edge of reading contents rather than the archive: this cataloger sees exactly what the
	// extraction produced. An archive truncated by a limit yields a package built from the entries
	// that were written, so identity degrades rather than disappearing - the manifest is there and the
	// maven metadata is not.
	//
	// Observed on a real artifact: jenkins-core-2.578.jar holds more than the default 10,000-entry
	// bound, so its META-INF/maven pom is never extracted and its group id falls back from
	// org.jenkins-ci.main to the artifact id. The archive-reading cataloger never felt this, because it
	// read the archive's own central directory with no bound on it.
	entries := map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n" +
			"Implementation-Title: example-lib\nImplementation-Version: 1.2.3\n",
		// the pom that would have supplied the group id is missing, as truncation would leave it
		"com/example/Thing.class": "not really bytecode",
	}

	dir := t.TempDir()
	explode(t, dir, entries)
	resolver, err := fileresolver.NewFromDirectory(dir, "")
	require.NoError(t, err)

	ctx := archive.WithTraversal(context.Background(), &archive.Traversal{
		Location:    file.NewLocation("example-lib-1.2.3.jar"),
		VirtualPath: "example-lib-1.2.3.jar",
		Depth:       1,
	})
	pkgs, _, err := NewArchiveContentsCataloger(DefaultArchiveCatalogerConfig()).Catalog(ctx, resolver)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "example-lib", pkgs[0].Name)
	assert.Equal(t, "1.2.3", pkgs[0].Version)
	assert.Equal(t, "pkg:maven/example-lib/example-lib@1.2.3", pkgs[0].PURL,
		"with no pom to name the group, the group falls back to the artifact id")
}

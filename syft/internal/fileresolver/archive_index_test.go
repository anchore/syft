package fileresolver

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/syft/file"
)

// storeWith builds an entry store holding the given entries, in name order so a test that depends on
// order is not depending on a map.
func storeWith(t *testing.T, maxInMemory int64, entries map[string]string) *archive.EntryStore {
	t.Helper()
	store := archive.NewEntryStore(t.TempDir(), "test.jar", nil)
	// how much stays in memory is the limiter's answer, so a test that wants content on disk sets a
	// memory bound and leaves disk unbounded
	charge := archive.NewLimiter(archive.Limits{MaxMemoryBytes: maxInMemory, MaxDiskBytes: -1}).Charge()
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		body := entries[name]
		hdr := tar.Header{Name: name, Size: int64(len(body)), Mode: 0o600, Typeflag: tar.TypeReg}
		if body == "" && name[len(name)-1] == '/' {
			hdr = tar.Header{Name: name, Mode: 0o755, Typeflag: tar.TypeDir}
			_, err := store.Add(hdr, nil, charge)
			require.NoError(t, err)
			continue
		}
		_, err := store.Add(hdr, bytes.NewReader([]byte(body)), charge)
		require.NoError(t, err)
	}
	return store
}

func indexOver(t *testing.T, maxInMemory int64, entries map[string]string, filters ...PathIndexVisitor) *ArchiveIndex {
	t.Helper()
	root := t.TempDir()
	r, err := NewFromArchiveEntries(root, "", "outer.jar", storeWith(t, maxInMemory, entries), false, filters...)
	require.NoError(t, err)
	return r
}

func relPaths(t *testing.T, r *ArchiveIndex, locations []file.Location) []string {
	t.Helper()
	var out []string
	for _, loc := range locations {
		out = append(out, "/"+loc.RealPath)
	}
	sort.Strings(out)
	return out
}

var jarEntriesFixture = map[string]string{
	"META-INF/MANIFEST.MF":                          "Manifest-Version: 1.0\n",
	"META-INF/maven/com.example/lib/pom.properties": "groupId=com.example\n",
	"META-INF/maven/com.example/lib/pom.xml":        "<project/>",
	"LICENSE":                                       "Apache License 2.0",
	"BOOT-INF/lib/inner.jar":                        "PK\x03\x04 not really",
	"com/example/Thing.class":                       "bytecode",
}

func TestArchiveIndex_globByExtensionUsesTheNameIndex(t *testing.T) {
	r := indexOver(t, 1<<20, jarEntriesFixture)

	locations, err := r.FilesByGlob("**/*.jar")
	require.NoError(t, err)
	assert.Equal(t, []string{"/BOOT-INF/lib/inner.jar"}, relPaths(t, r, locations))
}

func TestArchiveIndex_globByExactNameAtAnyDepth(t *testing.T) {
	r := indexOver(t, 1<<20, jarEntriesFixture)

	locations, err := r.FilesByGlob("**/pom.properties")
	require.NoError(t, err)
	assert.Equal(t, []string{"/META-INF/maven/com.example/lib/pom.properties"}, relPaths(t, r, locations))
}

func TestArchiveIndex_globFindsRootLevelFiles(t *testing.T) {
	// what the tar-backed resolver could not do: `/*` matched nothing there, so a jar carrying its
	// license at the root - kafka-clients does - lost it
	r := indexOver(t, 1<<20, jarEntriesFixture)

	locations, err := r.FilesByGlob("/*")
	require.NoError(t, err)
	assert.Equal(t, []string{"/LICENSE"}, relPaths(t, r, locations))
}

func TestArchiveIndex_globOneDirectoryDeep(t *testing.T) {
	r := indexOver(t, 1<<20, jarEntriesFixture)

	locations, err := r.FilesByGlob("/META-INF/*")
	require.NoError(t, err)
	assert.Equal(t, []string{"/META-INF/MANIFEST.MF"}, relPaths(t, r, locations),
		"one level only: the maven files are deeper")
}

func TestArchiveIndex_globAcrossSyntheticDirectories(t *testing.T) {
	// the archive never names META-INF/ or META-INF/maven/, so the directories a middle segment needs
	// have to be synthesized from the paths of the entries that were named
	r := indexOver(t, 1<<20, jarEntriesFixture)

	locations, err := r.FilesByGlob("**/maven/*/*/pom.xml")
	require.NoError(t, err)
	assert.Equal(t, []string{"/META-INF/maven/com.example/lib/pom.xml"}, relPaths(t, r, locations))
}

func TestArchiveIndex_pathsAndContents(t *testing.T) {
	r := indexOver(t, 1<<20, jarEntriesFixture)

	locations, err := r.FilesByPath("/META-INF/MANIFEST.MF")
	require.NoError(t, err)
	require.Len(t, locations, 1)

	assert.True(t, r.HasPath("/META-INF/MANIFEST.MF"))
	assert.True(t, r.HasPath("META-INF/MANIFEST.MF"), "a path may arrive with or without the leading slash")
	assert.False(t, r.HasPath("/nope"))

	reader, err := r.FileContentsByLocation(locations[0])
	require.NoError(t, err)
	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	assert.Equal(t, "Manifest-Version: 1.0\n", string(body))
}

func TestArchiveIndex_contentsSurviveTheMoveToDisk(t *testing.T) {
	// the index is built over entries, not offsets, so content moving out to the overflow blob must be
	// invisible to every lookup
	r := indexOver(t, 8, jarEntriesFixture)

	locations, err := r.FilesByGlob("**/*.jar")
	require.NoError(t, err)
	require.Len(t, locations, 1)

	reader, err := r.FileContentsByLocation(locations[0])
	require.NoError(t, err)
	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	assert.Equal(t, "PK\x03\x04 not really", string(body))
}

func TestArchiveIndex_mimeTypesAreSniffedFromContent(t *testing.T) {
	r := indexOver(t, 1<<20, map[string]string{
		"notes.txt": "just some text",
		"run.sh":    "#!/bin/bash\necho hello\n",
	})

	locations, err := r.FilesByMIMEType("text/x-shellscript")
	require.NoError(t, err)
	assert.Equal(t, []string{"/run.sh"}, relPaths(t, r, locations))
}

func TestArchiveIndex_exclusionsPruneWholeSubtrees(t *testing.T) {
	// a filter answering SkipDir removes the directory and everything under it, the way it would in a
	// directory walk. A tar is a sequence rather than a walk, so this is checked per entry against
	// what was pruned.
	skipMetaInf := func(_, entryPath string, info os.FileInfo, _ error) error {
		if strings.HasSuffix(entryPath, "/META-INF") || strings.HasSuffix(entryPath, "/META-INF/") {
			return filepath.SkipDir
		}
		_ = info
		return nil
	}

	// the archive names the directory itself, so the filter has something to prune on
	entries := map[string]string{}
	for k, v := range jarEntriesFixture {
		entries[k] = v
	}
	entries["META-INF/"] = ""

	r := indexOver(t, 1<<20, entries, skipMetaInf)

	locations, err := r.FilesByGlob("**/*")
	require.NoError(t, err)
	got := relPaths(t, r, locations)
	assert.NotContains(t, got, "/META-INF/MANIFEST.MF")
	assert.NotContains(t, got, "/META-INF/maven/com.example/lib/pom.xml")
	assert.Contains(t, got, "/LICENSE", "everything outside the pruned subtree is still there")
}

func TestArchiveIndex_allLocationsCoversEveryFile(t *testing.T) {
	r := indexOver(t, 1<<20, jarEntriesFixture)

	var got []string
	for loc := range r.AllLocations(context.Background()) {
		got = append(got, "/"+loc.RealPath)
	}
	sort.Strings(got)

	assert.Equal(t, []string{
		"/BOOT-INF/lib/inner.jar",
		"/LICENSE",
		"/META-INF/MANIFEST.MF",
		"/META-INF/maven/com.example/lib/pom.properties",
		"/META-INF/maven/com.example/lib/pom.xml",
		"/com/example/Thing.class",
	}, got)
}

func TestArchiveIndex_recordsCountsWhatTheFilesystemHolds(t *testing.T) {
	r := indexOver(t, 1<<20, jarEntriesFixture)
	assert.Equal(t, len(jarEntriesFixture), r.Records())
	assert.False(t, r.IndexTruncated())
}

func TestArchiveIndex_answersAreOrdered(t *testing.T) {
	// every answer has to come back in the same order every time. The archive walk enters archives in
	// the order it is handed them and merges what it finds into one shared SBOM, so the order decides
	// which locations group into which package - and an index built over a Go map has no order at all.
	//
	// Measured on trinodb/trino, whose plugin jars are hard links to one another: unordered, one
	// libzstd package holding 24 locations came back as three packages holding 6, 9 and 9 of the same
	// 24, and the image reported 7508 packages instead of 7506.
	entries := map[string]string{}
	for _, name := range []string{
		"b/z.jar", "a/y.jar", "c/x.jar", "a/b/c/w.jar", "z.jar", "a.jar",
	} {
		entries[name] = "PK\x03\x04 not really"
	}
	r := indexOver(t, 1<<20, entries)

	first, err := r.FilesByGlob("**/*.jar")
	require.NoError(t, err)
	require.Len(t, first, len(entries))

	byMIME, err := r.FilesByMIMEType("application/octet-stream")
	require.NoError(t, err)

	for range 8 {
		again, err := r.FilesByGlob("**/*.jar")
		require.NoError(t, err)
		assert.Equal(t, first, again, "the same glob must return the same order every time")

		mimeAgain, err := r.FilesByMIMEType("application/octet-stream")
		require.NoError(t, err)
		assert.Equal(t, byMIME, mimeAgain, "and so must a MIME lookup")

		var all []string
		for loc := range r.AllLocations(context.Background()) {
			all = append(all, loc.RealPath)
		}
		assert.True(t, sort.StringsAreSorted(all), "AllLocations must be ordered, not merely repeatable")
	}

	var paths []string
	for _, loc := range first {
		paths = append(paths, loc.RealPath)
	}
	assert.True(t, sort.StringsAreSorted(paths), "and the order is by path, so it is predictable rather than merely stable")
}

func TestArchiveIndex_CloseReleasesStore(t *testing.T) {
	// forcing content to disk (memory 0) so the store holds an open overflow blob, then Close must
	// release it; reads after Close no longer resolve, and a second Close is a no-op.
	r := indexOver(t, 0, map[string]string{"a.txt": "hello"})

	locs, err := r.FilesByPath("a.txt")
	require.NoError(t, err)
	require.Len(t, locs, 1)

	rc, err := r.FileContentsByLocation(locs[0])
	require.NoError(t, err)
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, "hello", string(b))

	require.NoError(t, r.Close())

	_, err = r.FileContentsByLocation(locs[0])
	assert.Error(t, err, "the overflow blob is closed, so its content can no longer be read")

	assert.NoError(t, r.Close(), "Close is idempotent")
}

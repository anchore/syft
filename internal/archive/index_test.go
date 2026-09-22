package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func TestIndex_globByExtensionUsesTheNameIndex(t *testing.T) {
	r := indexOver(t, 1<<20, jarEntriesFixture)

	locations, err := r.FilesByGlob("**/*.jar")
	require.NoError(t, err)
	assert.Equal(t, []string{"/BOOT-INF/lib/inner.jar"}, relPaths(t, r, locations))
}

func TestIndex_globByExactNameAtAnyDepth(t *testing.T) {
	r := indexOver(t, 1<<20, jarEntriesFixture)

	locations, err := r.FilesByGlob("**/pom.properties")
	require.NoError(t, err)
	assert.Equal(t, []string{"/META-INF/maven/com.example/lib/pom.properties"}, relPaths(t, r, locations))
}

func TestIndex_globFindsRootLevelFiles(t *testing.T) {
	r := indexOver(t, 1<<20, jarEntriesFixture)

	locations, err := r.FilesByGlob("/*")
	require.NoError(t, err)
	assert.Equal(t, []string{"/LICENSE"}, relPaths(t, r, locations))
}

func TestIndex_globOneDirectoryDeep(t *testing.T) {
	r := indexOver(t, 1<<20, jarEntriesFixture)

	locations, err := r.FilesByGlob("/META-INF/*")
	require.NoError(t, err)
	assert.Equal(t, []string{"/META-INF/MANIFEST.MF"}, relPaths(t, r, locations),
		"one level only: the maven files are deeper")
}

func TestIndex_globAcrossSyntheticDirectories(t *testing.T) {
	// the archive never lists META-INF/ or META-INF/maven/
	r := indexOver(t, 1<<20, jarEntriesFixture)

	locations, err := r.FilesByGlob("**/maven/*/*/pom.xml")
	require.NoError(t, err)
	assert.Equal(t, []string{"/META-INF/maven/com.example/lib/pom.xml"}, relPaths(t, r, locations))
}

func TestIndex_globHonorsNonWildcardMetacharacters(t *testing.T) {
	// a segment with any metacharacter other than one `*` must reach doublestar rather than be looked
	// up as a literal name
	r := indexOver(t, 1<<20, map[string]string{
		"usr/local/go/bin/go":                "binary",
		"usr/lib/libstd-0123456789abcdef.so": "binary",
		"opt/a.jar":                          "PK\x03\x04",
		"opt/b.war":                          "PK\x03\x04",
		"opt/notes.txt":                      "prose",
	})

	tests := []struct {
		pattern string
		want    []string
	}{
		{"**/{go,go.exe}", []string{"/usr/local/go/bin/go"}},
		{"**/libstd-????????????????.so", []string{"/usr/lib/libstd-0123456789abcdef.so"}},
		{"**/*.[jw]ar", []string{"/opt/a.jar", "/opt/b.war"}},
		{"**/{a,b}.{jar,war}", []string{"/opt/a.jar", "/opt/b.war"}},
		{"**/*.jar", []string{"/opt/a.jar"}},
		{"**/go", []string{"/usr/local/go/bin/go"}},
		{"**/notes*", []string{"/opt/notes.txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			locations, err := r.FilesByGlob(tt.pattern)
			require.NoError(t, err)
			assert.Equal(t, tt.want, relPaths(t, r, locations))
		})
	}
}

func TestIndex_globMetacharactersInAMiddleSegment(t *testing.T) {
	r := indexOver(t, 1<<20, map[string]string{
		"META-INF/maven/com.example/lib/pom.xml": "<project/>",
		"WEB-INF/lib/dep.jar":                    "PK\x03\x04",
	})

	locations, err := r.FilesByGlob("/{META-INF,WEB-INF}/**/*.xml")
	require.NoError(t, err)
	assert.Equal(t, []string{"/META-INF/maven/com.example/lib/pom.xml"}, relPaths(t, r, locations))
}

func TestIndex_pathsAndContents(t *testing.T) {
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

func TestIndex_contentsSurviveTheMoveToDisk(t *testing.T) {
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

func TestIndex_mimeTypesAreSniffedFromContent(t *testing.T) {
	r := indexOver(t, 1<<20, map[string]string{
		"notes.txt": "just some text",
		"run.sh":    "#!/bin/bash\necho hello\n",
	})

	locations, err := r.FilesByMIMEType("text/x-shellscript")
	require.NoError(t, err)
	assert.Equal(t, []string{"/run.sh"}, relPaths(t, r, locations))
}

func TestIndex_allLocationsCoversEveryFile(t *testing.T) {
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

func TestIndex_answersAreOrdered(t *testing.T) {
	// order decides which locations group into which package when results merge into the SBOM
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
		assert.Equal(t, first, again)

		mimeAgain, err := r.FilesByMIMEType("application/octet-stream")
		require.NoError(t, err)
		assert.Equal(t, byMIME, mimeAgain)

		var all []string
		for loc := range r.AllLocations(context.Background()) {
			all = append(all, loc.RealPath)
		}
		assert.True(t, sort.StringsAreSorted(all))
	}

	var paths []string
	for _, loc := range first {
		paths = append(paths, loc.RealPath)
	}
	assert.True(t, sort.StringsAreSorted(paths), "ordered by path, not merely stable")
}

// storeWith builds an entry store holding the given entries in name order. A name ending in "/" with
// an empty body is a directory.
func storeWith(t testing.TB, maxInMemory int64, entries map[string]string) *EntryStore {
	t.Helper()
	store := storeFor(t, memCharge(maxInMemory))

	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		body := entries[name]
		if body == "" && name[len(name)-1] == '/' {
			require.NoError(t, store.Add(tar.Header{Name: name, Mode: 0o755, Typeflag: tar.TypeDir}, nil))
			continue
		}
		require.NoError(t, store.Add(regularHeader(name, int64(len(body))), bytes.NewReader([]byte(body))))
	}
	return store
}

func indexOver(t testing.TB, maxInMemory int64, entries map[string]string) *Index {
	t.Helper()
	return NewIndex(storeWith(t, maxInMemory, entries), "", "outer.jar")
}

func relPaths(t *testing.T, r *Index, locations []file.Location) []string {
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

func TestIndex_impliedDirectoriesArePathsButNotFiles(t *testing.T) {
	r := indexOver(t, 1<<20, jarEntriesFixture)

	assert.True(t, r.HasPath("META-INF"))
	assert.True(t, r.HasPath("/META-INF/maven"))

	locations, err := r.FilesByPath("META-INF")
	require.NoError(t, err)
	assert.Empty(t, locations)
	locations, err = r.FilesByGlob("**/maven")
	require.NoError(t, err)
	assert.Empty(t, locations)
}

func TestIndex_invalidGlobIsAnError(t *testing.T) {
	r := indexOver(t, 1<<20, jarEntriesFixture)
	_, err := r.FilesByGlob("**/[")
	assert.Error(t, err)
}

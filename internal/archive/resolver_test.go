package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
)

var jarEntriesFixture = map[string]string{
	"META-INF/MANIFEST.MF":                          "Manifest-Version: 1.0\n",
	"META-INF/maven/com.example/lib/pom.properties": "groupId=com.example\n",
	"META-INF/maven/com.example/lib/pom.xml":        "<project/>",
	"LICENSE":                                       "Apache License 2.0",
	"BOOT-INF/lib/inner.jar":                        "PK\x03\x04 not really",
	"com/example/Thing.class":                       "bytecode",
}

func TestResolver_add_refusedEntryIsNotStored(t *testing.T) {
	// a half-stored pom a cataloger parses is worse than an absent one
	r, _ := resolverIn(t, NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: 0}).charge())

	err := r.add(regularHeader("a.txt", 3), bytes.NewReader([]byte("abc")))
	assert.ErrorIs(t, err, ErrDiskLimitReached)
	assert.Empty(t, storedNames(t, r))
	assert.False(t, r.HasPath("a.txt"))
}

func TestResolver_add_refusedContentLeavesNoNodeBehind(t *testing.T) {
	// the index estimate is admitted, then the content is refused
	record := approxIndexBytes(regularHeader("dir/a.txt", 0)) + approxIndexBytesPerEntry // the entry and the directory it implies
	r, _ := resolverIn(t, diskCharge(record+2))

	err := r.add(regularHeader("dir/a.txt", 3), bytes.NewReader([]byte("abc")))
	assert.ErrorIs(t, err, ErrDiskLimitReached)
	assert.False(t, r.HasPath("dir/a.txt"))
	assert.True(t, r.HasPath("dir"), "the directories it implied stay")
}

func TestResolver_add_directoryEntriesHoldNoContent(t *testing.T) {
	r, _ := resolverIn(t, memCharge(1<<20))

	require.NoError(t, r.add(tar.Header{Name: "lib", Typeflag: tar.TypeDir, Mode: 0o755}, nil))

	assert.Zero(t, r.heldInMemory())
	assert.Empty(t, readStore(t, r)["lib"].body)
}

func TestResolver_add_indexDoesNotFallBackToDiskWhenMemoryIsBounded(t *testing.T) {
	// the index lives in memory, so a bounded memory limit bounds it; only a zero limit defers to disk
	limiter := NewLimiter(Limits{MaxMemoryBytes: 1024, MaxDiskBytes: -1})
	r, _ := resolverIn(t, limiter.charge())

	err := r.add(regularHeader("a.txt", 0), bytes.NewReader(nil))
	assert.ErrorIs(t, err, ErrDiskLimitReached)
	_, disk := limiter.InUse()
	assert.Zero(t, disk)
}

func TestResolver_add_indexMakesRoomBySpillingHeldContent(t *testing.T) {
	record := approxIndexBytes(regularHeader("a.txt", 0))
	r, dir := resolverIn(t, memCharge(2*record+50))

	require.NoError(t, r.add(regularHeader("a.txt", 100), bytes.NewReader(bytes.Repeat([]byte("a"), 100))))
	require.Equal(t, int64(100), r.heldInMemory())

	// b's index does not fit beside a's content, so a's content moves to disk and b is indexed
	require.NoError(t, r.add(regularHeader("b.txt", 3), bytes.NewReader([]byte("bbb"))))
	r.finish()

	assert.Equal(t, int64(3), r.heldInMemory())
	assert.NotEmpty(t, spillFile(t, dir))
	assert.Equal(t, []string{"a.txt", "b.txt"}, storedNames(t, r))
	assert.Equal(t, strings.Repeat("a", 100), readStore(t, r)["a.txt"].body)
}

func TestResolver_add_lastEntryAtAPathWins(t *testing.T) {
	r, _ := resolverIn(t, memCharge(1<<20))

	require.NoError(t, r.add(regularHeader("a.txt", 5), bytes.NewReader([]byte("first"))))
	require.NoError(t, r.add(regularHeader("a.txt", 6), bytes.NewReader([]byte("second"))))
	require.NoError(t, r.add(regularHeader("b.txt", 1), bytes.NewReader([]byte("b"))))
	require.NoError(t, r.add(tar.Header{Name: "b.txt", Typeflag: tar.TypeSymlink, Linkname: "a.txt"}, nil))
	r.finish()

	assert.Equal(t, "second", readStore(t, r)["a.txt"].body)
	assert.Equal(t, "a.txt", readStore(t, r)["b.txt"].linkTarget, "a later entry may change kind")
	assert.Equal(t, 2, r.entries)
	assert.Equal(t, int64(len("second")), r.heldInMemory(), "the earlier copy is refunded")

	locations, err := r.FilesByGlob("**/a.txt")
	require.NoError(t, err)
	require.Len(t, locations, 1)
	reader, err := r.FileContentsByLocation(locations[0])
	require.NoError(t, err)
	assert.Equal(t, "second", readEntry(t, reader.(entryReader).ReaderAtSeeker))
}

func TestResolver_add_fileAndDirectoryAtOnePathKeepsTheFirst(t *testing.T) {
	r, _ := resolverIn(t, memCharge(1<<20))

	require.NoError(t, r.add(regularHeader("a/b", 1), bytes.NewReader([]byte("x"))))
	require.NoError(t, r.add(regularHeader("a", 4), bytes.NewReader([]byte("file"))))
	require.NoError(t, r.add(regularHeader("c", 4), bytes.NewReader([]byte("file"))))
	require.NoError(t, r.add(tar.Header{Name: "c", Typeflag: tar.TypeDir, Mode: 0o755}, nil))
	r.finish()

	got := readStore(t, r)
	assert.Equal(t, stereoscopeFile.TypeDirectory, got["a"].kind)
	assert.Equal(t, "file", got["c"].body)
}

func TestResolver_pathsAndContents(t *testing.T) {
	r := resolverOver(t, 1<<20, jarEntriesFixture)

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

func TestResolver_fullPathsOutsideTheArchiveNameNothing(t *testing.T) {
	r, _ := resolverIn(t, memCharge(1<<20))
	r.archiveCoordinates = file.Coordinates{RealPath: "/app.war", FullPath: "/app.war!/WEB-INF/lib/dep.jar"}
	addAll(t, r, fileEntries(map[string]string{"/app.war": "same name", "/META-INF/MANIFEST.MF": "m"}))

	locations, err := r.FilesByPath("/app.war!/WEB-INF/lib/dep.jar!/META-INF/MANIFEST.MF")
	require.NoError(t, err)
	assert.Len(t, locations, 1, "a full path in this archive")

	for _, p := range []string{"/app.war!/WEB-INF/lib/dep.jar", "/app.war!/WEB-INF/lib/other.jar!/META-INF/MANIFEST.MF"} {
		locations, err = r.FilesByPath(p)
		require.NoError(t, err)
		assert.Empty(t, locations, "%s is outside the archive", p)
		assert.False(t, r.HasPath(p), p)
	}

	for _, p := range []string{"app.war", "/app.war"} {
		locations, err = r.FilesByPath(p)
		require.NoError(t, err)
		require.Len(t, locations, 1, "%s is an entry path named like the outermost archive", p)
		assert.Equal(t, "/app.war!/WEB-INF/lib/dep.jar!/app.war", locations[0].FullPath, p)
	}

	again, err := r.FilesByPath(locations[0].LocalPath())
	require.NoError(t, err)
	assert.Equal(t, locations, again, "a LocalPath finds its own entry")
}

func TestResolver_mimeTypesAreSniffedFromContent(t *testing.T) {
	r := resolverOver(t, 1<<20, map[string]string{
		"notes.txt": "just some text",
		"run.sh":    "#!/bin/bash\necho hello\n",
	})

	locations, err := r.FilesByMIMEType("text/x-shellscript")
	require.NoError(t, err)
	assert.Equal(t, []string{"/run.sh"}, localPaths(locations))
}

func TestResolver_answersAreOrdered(t *testing.T) {
	// order decides which locations group into which package when results merge into the SBOM
	entries := map[string]string{}
	for _, name := range []string{
		"b/z.jar", "a/y.jar", "c/x.jar", "a/b/c/w.jar", "z.jar", "a.jar",
	} {
		entries[name] = "PK\x03\x04 not really"
	}
	r := resolverOver(t, 1<<20, entries)

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
			all = append(all, loc.LocalPath())
		}
		assert.True(t, sort.StringsAreSorted(all))
	}

	var paths []string
	for _, loc := range first {
		paths = append(paths, loc.LocalPath())
	}
	assert.True(t, sort.StringsAreSorted(paths), "ordered by path, not merely stable")
}

func TestResolver_impliedDirectoriesArePathsButNotFiles(t *testing.T) {
	r := resolverOver(t, 1<<20, jarEntriesFixture)

	assert.True(t, r.HasPath("META-INF"))
	assert.True(t, r.HasPath("/META-INF/maven"))

	locations, err := r.FilesByPath("META-INF")
	require.NoError(t, err)
	assert.Empty(t, locations)
	locations, err = r.FilesByGlob("**/maven")
	require.NoError(t, err)
	assert.Empty(t, locations)
}

// stereoscope finds a directory's children by looking the directory up by name: directories the archive
// never listed must be indexed, and the root, which has no name, answered another way
func TestResolver_globsForADirectorysChildren(t *testing.T) {
	r := resolverOver(t, 1<<20, map[string]string{
		"LICENSE":                    "root",
		"META-INF/LICENSE.txt":       "nested",
		"META-INF/maven/g/a/pom.xml": "deeper",
	})

	assert.Equal(t, []string{"/LICENSE"}, globPaths(t, r, "/*"))
	assert.Equal(t, []string{"/LICENSE"}, globPaths(t, r, "*"))
	assert.Equal(t, []string{"/META-INF/LICENSE.txt"}, globPaths(t, r, "/META-INF/*"))
	assert.Equal(t, []string{"/META-INF/LICENSE.txt"}, globPaths(t, r, "META-INF/*"))
	assert.Equal(t, []string{"/META-INF/maven/g/a/pom.xml"}, globPaths(t, r, "**/a/*"))
}

func TestResolver_invalidGlobIsAnError(t *testing.T) {
	r := resolverOver(t, 1<<20, jarEntriesFixture)
	_, err := r.FilesByGlob("**/[")
	assert.Error(t, err)
}

func globPaths(t *testing.T, r *Resolver, pattern string) []string {
	t.Helper()
	locations, err := r.FilesByGlob(pattern)
	require.NoError(t, err)
	return localPaths(locations)
}

// several paths to one file answer as one location: the file's own path when it matched, otherwise
// the lowest-sorting link
func TestResolver_linksCollapseToOnePath(t *testing.T) {
	tests := []struct {
		name    string
		entries []testEntry
		pattern string
		want    []string
		reason  string
	}{
		{
			name: "the file itself beats every link to it",
			entries: []testEntry{
				{name: "opt/real.jar", body: "PK\x03\x04"},
				{name: "opt/a-sym.jar", link: "real.jar"},
				{name: "opt/z-sym.jar", link: "real.jar"},
				{name: "opt/hard.jar", link: "opt/real.jar", hard: true},
			},
			pattern: "**/*.jar",
			want:    []string{"/opt/real.jar"},
			reason:  "one file, so one location - and it is named by the path that holds it",
		},
		{
			name: "with no candidate naming the file, the lowest-sorting link wins",
			entries: []testEntry{
				{name: "opt/real.bin", body: "PK\x03\x04"},
				{name: "opt/z-sym.jar", link: "real.bin"},
				{name: "opt/a-sym.jar", link: "real.bin"},
				{name: "opt/m-sym.jar", link: "real.bin"},
			},
			pattern: "**/*.jar",
			want:    []string{"/opt/real.bin"},
			reason:  "the content is the target's, so that is the real path the answer carries",
		},
		{
			name: "distinct files stay distinct",
			entries: []testEntry{
				{name: "opt/one.jar", body: "one"},
				{name: "opt/two.jar", body: "two"},
				{name: "opt/one-sym.jar", link: "one.jar"},
			},
			pattern: "**/*.jar",
			want:    []string{"/opt/one.jar", "/opt/two.jar"},
			reason:  "collapsing is per file, not per pattern",
		},
		{
			name: "a dangling link is not a file",
			entries: []testEntry{
				{name: "opt/real.jar", body: "PK\x03\x04"},
				{name: "opt/gone.jar", link: "missing.jar"},
			},
			pattern: "**/*.jar",
			want:    []string{"/opt/real.jar"},
			reason:  "it names no content",
		},
		{
			name: "two dangling links are two paths, not one",
			entries: []testEntry{
				{name: "opt/a.jar", link: "missing.jar"},
				{name: "opt/b.jar", link: "missing.jar"},
			},
			pattern: "**/*.jar",
			want:    nil,
			reason:  "a link to nothing is not a file",
		},
		{
			name: "a chain of links collapses onto the file at its end",
			entries: []testEntry{
				{name: "opt/real.jar", body: "PK\x03\x04"},
				{name: "opt/mid.jar", link: "real.jar"},
				{name: "opt/outer.jar", link: "mid.jar"},
			},
			pattern: "**/*.jar",
			want:    []string{"/opt/real.jar"},
			reason:  "following one hop at a time reaches the same file from every path",
		},
		{
			name: "a cycle resolves to nothing rather than looping",
			entries: []testEntry{
				{name: "opt/a.jar", link: "b.jar"},
				{name: "opt/b.jar", link: "a.jar"},
			},
			pattern: "**/*.jar",
			want:    nil,
			reason:  "neither reaches a file",
		},
		{
			name: "a hard link resolves from the archive root, not from its own directory",
			entries: []testEntry{
				{name: "opt/real.jar", body: "PK\x03\x04"},
				{name: "opt/nested/hard.jar", link: "opt/real.jar", hard: true},
			},
			pattern: "**/*.jar",
			want:    []string{"/opt/real.jar"},
			reason:  "read as relative it would resolve to opt/nested/opt/real.jar and dangle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolverFrom(t, tt.entries...)
			assert.Equal(t, tt.want, globPaths(t, r, tt.pattern), tt.reason)
		})
	}
}

func TestResolver_collapsedLocationReadsTheTarget(t *testing.T) {
	r := resolverFrom(t,
		testEntry{name: "opt/real.bin", body: "PK\x03\x04 real contents"},
		testEntry{name: "opt/a-sym.jar", link: "real.bin"},
		testEntry{name: "opt/z-sym.jar", link: "real.bin"},
	)

	locations, err := r.FilesByGlob("**/*.jar")
	require.NoError(t, err)
	require.Len(t, locations, 1)

	assert.Equal(t, "/opt/real.bin", locations[0].LocalPath(), "content comes from the file")
	assert.Equal(t, "outer.jar!/opt/a-sym.jar", locations[0].AccessPath, "the path searched by is the one matched")

	reader, err := r.FileContentsByLocation(locations[0])
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reader.Close()) })

	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "PK\x03\x04 real contents", string(body),
		"a location standing for a link must still read the file's bytes, not the link's none")
}

func TestResolver_fullPathsAreTrimmedToEntryPaths(t *testing.T) {
	// catalogers build queries from the full paths the resolver hands out, e.g. path.Dir plus a sibling
	r := resolverOver(t, 1<<20, map[string]string{"pom.xml": "a", "lib/dep.jar": "b"})

	locations, err := r.FilesByPath("outer.jar!/lib/dep.jar")
	require.NoError(t, err)
	require.Len(t, locations, 1)
	assert.Equal(t, "outer.jar!/lib/dep.jar", locations[0].AccessPath)

	locations, err = r.FilesByPath(path.Join(path.Dir(locations[0].AccessPath), "../pom.xml"))
	require.NoError(t, err)
	require.Len(t, locations, 1, "a sibling at the archive root is reached through the full path")
	assert.Equal(t, "outer.jar!/pom.xml", locations[0].FullNestedPath())

	assert.True(t, r.HasPath(path.Dir("outer.jar!/pom.xml")), "the directory of a root entry is the root")
	assert.True(t, r.HasPath("lib/dep.jar"), "an entry path is still accepted")

	locations, err = r.FilesByGlob("outer.jar!/**/*.jar")
	require.NoError(t, err)
	require.Len(t, locations, 1)
}

func TestResolver_danglingLinkHasNoContent(t *testing.T) {
	r := resolverFrom(t, testEntry{name: "opt/gone.jar", link: "missing.jar"})

	var locations []file.Location
	for l := range r.AllLocations(context.Background()) {
		locations = append(locations, l)
	}
	require.Len(t, locations, 1)
	assert.Equal(t, "/opt/gone.jar", locations[0].LocalPath())

	_, err := r.FileContentsByLocation(locations[0])
	assert.Error(t, err, "a link to nothing has no content to read")

	metadata, err := r.FileMetadataByLocation(locations[0])
	require.NoError(t, err)
	assert.Equal(t, "outer.jar!/opt/missing.jar", metadata.LinkDestination,
		"where it pointed is still reported, resolved against the link's own directory")
}

func TestResolver_mimeTypeAnswersOnlyWithFiles(t *testing.T) {
	r := resolverFrom(t,
		testEntry{name: "opt/real.jar", body: "PK\x03\x04 zip contents here"},
		testEntry{name: "opt/sym.jar", link: "real.jar"},
		testEntry{name: "opt/hard.jar", link: "opt/real.jar", hard: true},
		testEntry{name: "opt/gone.jar", link: "missing.jar"},
		testEntry{name: "opt/notes.txt", body: "hello world"},
	)

	byMIME := func(types ...string) []string {
		t.Helper()
		locations, err := r.FilesByMIMEType(types...)
		require.NoError(t, err)
		return localPaths(locations)
	}

	assert.Equal(t, []string{"/opt/real.jar"}, byMIME("application/zip"),
		"the file answers, not the two links to it")
	assert.Equal(t, []string{"/opt/notes.txt"}, byMIME("text/plain"))
	assert.Empty(t, byMIME(""),
		"a link sniffs to no type, and must not be reachable by asking for that")
	assert.Equal(t, []string{"/opt/notes.txt", "/opt/real.jar"}, byMIME("application/zip", "text/plain"))
}

// AllLocations enumerates what the archive holds rather than searching for files: the file metadata
// cataloger records a row per path, links included
func TestResolver_allLocationsKeepsEveryPath(t *testing.T) {
	r := resolverFrom(t,
		testEntry{name: "opt/real.jar", body: "PK\x03\x04"},
		testEntry{name: "opt/sym.jar", link: "real.jar"},
		testEntry{name: "opt/gone.jar", link: "missing.jar"},
	)

	var got []string
	for l := range r.AllLocations(context.Background()) {
		got = append(got, l.LocalPath())
	}
	assert.Equal(t, []string{"/opt/gone.jar", "/opt/real.jar", "/opt/sym.jar"}, got,
		"every path the archive names, links included")
}

func TestResolver_add_anEntryOverTheCapIsSkippedAndReadNoFurther(t *testing.T) {
	// one entry of an overlapping-entry bomb can inflate without bound; it must stop at the cap, cost
	// the archive only that entry, and say so
	orig := maxEntryBytes
	maxEntryBytes = 1024
	t.Cleanup(func() { maxEntryBytes = orig })

	r, _ := resolverIn(t, memCharge(-1))
	endless := &countingReader{r: zeroSource{}}
	require.NoError(t, r.add(tar.Header{Name: "bomb.bin", Typeflag: tar.TypeReg, Mode: 0o644}, endless))
	require.NoError(t, r.add(tar.Header{Name: "ok.txt", Typeflag: tar.TypeReg, Mode: 0o644}, strings.NewReader("ok")))
	r.finish()

	assert.LessOrEqual(t, endless.n, 1024+copyChunkSize, "reading stops just past the cap")
	assert.ErrorIs(t, r.Truncated, errEntryTooLarge)
	assert.ErrorContains(t, r.Truncated, "per-entry size cap of 1.0 KiB")
	locations, err := r.FilesByGlob("**")
	require.NoError(t, err)
	assert.Equal(t, []string{"/ok.txt"}, localPaths(locations))
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

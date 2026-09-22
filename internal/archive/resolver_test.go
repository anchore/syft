package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestResolver_add_indexCostIsChargedEvenForEmptyContent(t *testing.T) {
	// the index estimate is what bounds an archive of many empty entries
	limiter := NewLimiter(Limits{MaxMemoryBytes: 1 << 20, MaxDiskBytes: -1})
	r, _ := resolverIn(t, limiter.charge())

	hdr := regularHeader("a.txt", 0)
	require.NoError(t, r.add(hdr, bytes.NewReader(nil)))

	mem, _ := limiter.InUse()
	assert.Equal(t, approxIndexBytes(hdr), mem)
	assert.Zero(t, r.heldInMemory())
}

func TestResolver_add_indexCostFallsBackToDiskWhenMemoryIsZero(t *testing.T) {
	limiter := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1})
	r, _ := resolverIn(t, limiter.charge())

	hdr := regularHeader("a.txt", 0)
	require.NoError(t, r.add(hdr, bytes.NewReader(nil)))

	mem, disk := limiter.InUse()
	assert.Zero(t, mem)
	assert.Equal(t, approxIndexBytes(hdr), disk)
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

func TestResolver_add_refusesEntriesWhenNoBudgetAdmitsTheIndex(t *testing.T) {
	room := approxIndexBytes(regularHeader("x0", 0)) * 3
	r, _ := resolverIn(t, NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: room}).charge())

	var err error
	admitted := 0
	for i := 0; i < 100 && err == nil; i++ {
		if err = r.add(regularHeader(fmt.Sprintf("x%d", i), 0), bytes.NewReader(nil)); err == nil {
			admitted++
		}
	}
	require.ErrorIs(t, err, ErrDiskLimitReached)
	assert.Equal(t, 3, admitted)
}

func TestResolver_add_firstEntryAtAPathWins(t *testing.T) {
	r, _ := resolverIn(t, memCharge(1<<20))

	require.NoError(t, r.add(regularHeader("a.txt", 5), bytes.NewReader([]byte("first"))))
	require.NoError(t, r.add(regularHeader("a.txt", 6), bytes.NewReader([]byte("second"))))
	r.finish()

	assert.Equal(t, "first", readStore(t, r)["a.txt"].body)
	assert.Len(t, r.files, 1)
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

func TestResolver_contentsSurviveTheMoveToDisk(t *testing.T) {
	// room for the index but only a few bytes of content, so the rest moves to disk
	r := resolverOver(t, indexCostOf(jarEntriesFixture)+8, jarEntriesFixture)

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

func TestResolver_mimeTypesAreSniffedFromContent(t *testing.T) {
	r := resolverOver(t, 1<<20, map[string]string{
		"notes.txt": "just some text",
		"run.sh":    "#!/bin/bash\necho hello\n",
	})

	locations, err := r.FilesByMIMEType("text/x-shellscript")
	require.NoError(t, err)
	assert.Equal(t, []string{"run.sh"}, realPaths(locations))
}

func TestResolver_allLocationsCoversEveryFile(t *testing.T) {
	r := resolverOver(t, 1<<20, jarEntriesFixture)

	var got []string
	for loc := range r.AllLocations(context.Background()) {
		got = append(got, loc.RealPath)
	}
	sort.Strings(got)

	assert.Equal(t, []string{
		"BOOT-INF/lib/inner.jar",
		"LICENSE",
		"META-INF/MANIFEST.MF",
		"META-INF/maven/com.example/lib/pom.properties",
		"META-INF/maven/com.example/lib/pom.xml",
		"com/example/Thing.class",
	}, got)
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

func TestResolver_invalidGlobIsAnError(t *testing.T) {
	r := resolverOver(t, 1<<20, jarEntriesFixture)
	_, err := r.FilesByGlob("**/[")
	assert.Error(t, err)
}

func globPaths(t *testing.T, r *Resolver, pattern string) []string {
	t.Helper()
	locations, err := r.FilesByGlob(pattern)
	require.NoError(t, err)
	return realPaths(locations)
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
			want:    []string{"opt/real.jar"},
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
			want:    []string{"opt/real.bin"},
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
			want:    []string{"opt/one.jar", "opt/two.jar"},
			reason:  "collapsing is per file, not per pattern",
		},
		{
			name: "a dangling link keeps its own path",
			entries: []testEntry{
				{name: "opt/real.jar", body: "PK\x03\x04"},
				{name: "opt/gone.jar", link: "missing.jar"},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/gone.jar", "opt/real.jar"},
			reason:  "it names no content, so it belongs to no other file's group",
		},
		{
			name: "two dangling links are two paths, not one",
			entries: []testEntry{
				{name: "opt/a.jar", link: "missing.jar"},
				{name: "opt/b.jar", link: "missing.jar"},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/a.jar", "opt/b.jar"},
			reason:  "nothing resolves them to a common file, so neither may absorb the other",
		},
		{
			name: "a chain of links collapses onto the file at its end",
			entries: []testEntry{
				{name: "opt/real.jar", body: "PK\x03\x04"},
				{name: "opt/mid.jar", link: "real.jar"},
				{name: "opt/outer.jar", link: "mid.jar"},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/real.jar"},
			reason:  "following one hop at a time reaches the same file from every path",
		},
		{
			name: "a cycle resolves to nothing rather than looping",
			entries: []testEntry{
				{name: "opt/a.jar", link: "b.jar"},
				{name: "opt/b.jar", link: "a.jar"},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/a.jar", "opt/b.jar"},
			reason:  "neither reaches content, so each stands under its own path",
		},
		{
			name: "a hard link resolves from the archive root, not from its own directory",
			entries: []testEntry{
				{name: "opt/real.jar", body: "PK\x03\x04"},
				{name: "opt/nested/hard.jar", link: "opt/real.jar", hard: true},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/real.jar"},
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

// the choice must not depend on the order the search found the candidates in
func TestResolver_collapseIgnoresTheOrderItFinds(t *testing.T) {
	r := resolverFrom(t,
		testEntry{name: "opt/real.jar", body: "PK\x03\x04"},
		testEntry{name: "opt/a-sym.jar", link: "real.jar"},
		testEntry{name: "opt/m-sym.jar", link: "real.jar"},
		testEntry{name: "opt/z-sym.jar", link: "real.jar"},
	)

	candidates := []*node{
		r.byPath["/opt/real.jar"], r.byPath["/opt/a-sym.jar"],
		r.byPath["/opt/m-sym.jar"], r.byPath["/opt/z-sym.jar"],
	}
	for _, n := range candidates {
		require.NotNil(t, n)
	}

	rng := rand.New(rand.NewSource(1))
	for range 64 {
		rng.Shuffle(len(candidates), func(i, j int) {
			candidates[i], candidates[j] = candidates[j], candidates[i]
		})

		found := map[*node]struct{}{}
		for _, n := range candidates {
			found[n] = struct{}{}
		}

		best := onePathPerFile(found)
		require.Len(t, best, 1, "four paths, one file")
		assert.Equal(t, "/opt/real.jar", best[0].path, "the file itself must win from any order")
	}

	// and with the file itself not among the candidates, the lowest-sorting link wins from any order
	links := candidates[:0:0]
	for _, n := range candidates {
		if n.path != "/opt/real.jar" {
			links = append(links, n)
		}
	}
	for range 64 {
		rng.Shuffle(len(links), func(i, j int) { links[i], links[j] = links[j], links[i] })

		found := map[*node]struct{}{}
		for _, n := range links {
			found[n] = struct{}{}
		}

		best := onePathPerFile(found)
		require.Len(t, best, 1)
		assert.Equal(t, "/opt/a-sym.jar", best[0].path, "the lowest-sorting link must win from any order")
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

	assert.Equal(t, "opt/real.bin", locations[0].RealPath, "content comes from the file")
	assert.Equal(t, "opt/a-sym.jar", locations[0].AccessPath, "the path searched by is the one matched")

	reader, err := r.FileContentsByLocation(locations[0])
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reader.Close()) })

	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "PK\x03\x04 real contents", string(body),
		"a location standing for a link must still read the file's bytes, not the link's none")
}

func TestResolver_danglingLinkHasNoContent(t *testing.T) {
	r := resolverFrom(t, testEntry{name: "opt/gone.jar", link: "missing.jar"})

	locations, err := r.FilesByGlob("**/*.jar")
	require.NoError(t, err)
	require.Len(t, locations, 1)
	assert.Equal(t, "opt/gone.jar", locations[0].RealPath)

	reader, err := r.FileContentsByLocation(locations[0])
	require.NoError(t, err)
	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Empty(t, string(body), "a link to nothing holds nothing")

	metadata, err := r.FileMetadataByLocation(locations[0])
	require.NoError(t, err)
	assert.Equal(t, "opt/missing.jar", metadata.LinkDestination,
		"where it pointed is still reported, resolved against the link's own directory")
}

// a link has no content to sniff a type from; the file it points at answers under its own path
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
		return realPaths(locations)
	}

	assert.Equal(t, []string{"opt/real.jar"}, byMIME("application/zip"),
		"the file answers, not the two links to it")
	assert.Equal(t, []string{"opt/notes.txt"}, byMIME("text/plain"))
	assert.Empty(t, byMIME(""),
		"a link sniffs to no type, and must not be reachable by asking for that")
	assert.Equal(t, []string{"opt/notes.txt", "opt/real.jar"}, byMIME("application/zip", "text/plain"))
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
		got = append(got, l.RealPath)
	}
	assert.Equal(t, []string{"opt/gone.jar", "opt/real.jar", "opt/sym.jar"}, got,
		"every path the archive names, links included")
}

package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// linkEntry is a regular file when linkname is empty, otherwise a symlink or, with hard set, a hard link.
type linkEntry struct {
	name     string
	body     string
	linkname string
	hard     bool
}

func indexWithLinks(t testing.TB, entries ...linkEntry) *Index {
	t.Helper()
	store := storeFor(t, memCharge(1<<20))
	for _, e := range entries {
		hdr := regularHeader(e.name, int64(len(e.body)))
		switch {
		case e.linkname != "" && e.hard:
			hdr = tar.Header{Name: e.name, Mode: 0o644, Typeflag: tar.TypeLink, Linkname: e.linkname}
		case e.linkname != "":
			hdr = tar.Header{Name: e.name, Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: e.linkname}
		}
		require.NoError(t, store.Add(hdr, bytes.NewReader([]byte(e.body))))
	}
	return NewIndex(store, "", "outer.tar")
}

func globPaths(t *testing.T, r *Index, pattern string) []string {
	t.Helper()
	locations, err := r.FilesByGlob(pattern)
	require.NoError(t, err)
	var out []string
	for _, l := range locations {
		out = append(out, l.RealPath)
	}
	return out
}

// several paths to one file answer as one location: the file's own path when it matched, otherwise
// the lowest-sorting link
func TestIndex_linksCollapseToOnePath(t *testing.T) {
	tests := []struct {
		name    string
		entries []linkEntry
		pattern string
		want    []string
		reason  string
	}{
		{
			name: "the file itself beats every link to it",
			entries: []linkEntry{
				{name: "opt/real.jar", body: "PK\x03\x04"},
				{name: "opt/a-sym.jar", linkname: "real.jar"},
				{name: "opt/z-sym.jar", linkname: "real.jar"},
				{name: "opt/hard.jar", linkname: "opt/real.jar", hard: true},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/real.jar"},
			reason:  "one file, so one location - and it is named by the path that holds it",
		},
		{
			name: "with no candidate naming the file, the lowest-sorting link wins",
			entries: []linkEntry{
				{name: "opt/real.bin", body: "PK\x03\x04"},
				{name: "opt/z-sym.jar", linkname: "real.bin"},
				{name: "opt/a-sym.jar", linkname: "real.bin"},
				{name: "opt/m-sym.jar", linkname: "real.bin"},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/real.bin"},
			reason:  "the content is the target's, so that is the real path the answer carries",
		},
		{
			name: "distinct files stay distinct",
			entries: []linkEntry{
				{name: "opt/one.jar", body: "one"},
				{name: "opt/two.jar", body: "two"},
				{name: "opt/one-sym.jar", linkname: "one.jar"},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/one.jar", "opt/two.jar"},
			reason:  "collapsing is per file, not per pattern",
		},
		{
			name: "a dangling link keeps its own path",
			entries: []linkEntry{
				{name: "opt/real.jar", body: "PK\x03\x04"},
				{name: "opt/gone.jar", linkname: "missing.jar"},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/gone.jar", "opt/real.jar"},
			reason:  "it names no content, so it belongs to no other file's group",
		},
		{
			name: "two dangling links are two paths, not one",
			entries: []linkEntry{
				{name: "opt/a.jar", linkname: "missing.jar"},
				{name: "opt/b.jar", linkname: "missing.jar"},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/a.jar", "opt/b.jar"},
			reason:  "nothing resolves them to a common file, so neither may absorb the other",
		},
		{
			name: "a chain of links collapses onto the file at its end",
			entries: []linkEntry{
				{name: "opt/real.jar", body: "PK\x03\x04"},
				{name: "opt/mid.jar", linkname: "real.jar"},
				{name: "opt/outer.jar", linkname: "mid.jar"},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/real.jar"},
			reason:  "following one hop at a time reaches the same file from every path",
		},
		{
			name: "a cycle resolves to nothing rather than looping",
			entries: []linkEntry{
				{name: "opt/a.jar", linkname: "b.jar"},
				{name: "opt/b.jar", linkname: "a.jar"},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/a.jar", "opt/b.jar"},
			reason:  "neither reaches content, so each stands under its own path",
		},
		{
			name: "a hard link resolves from the archive root, not from its own directory",
			entries: []linkEntry{
				{name: "opt/real.jar", body: "PK\x03\x04"},
				{name: "opt/nested/hard.jar", linkname: "opt/real.jar", hard: true},
			},
			pattern: "**/*.jar",
			want:    []string{"opt/real.jar"},
			reason:  "read as relative it would resolve to opt/nested/opt/real.jar and dangle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := indexWithLinks(t, tt.entries...)
			assert.Equal(t, tt.want, globPaths(t, r, tt.pattern), tt.reason)
		})
	}
}

// the choice must not depend on the order the search found the candidates in
func TestIndex_collapseIgnoresTheOrderItFinds(t *testing.T) {
	r := indexWithLinks(t,
		linkEntry{name: "opt/real.jar", body: "PK\x03\x04"},
		linkEntry{name: "opt/a-sym.jar", linkname: "real.jar"},
		linkEntry{name: "opt/m-sym.jar", linkname: "real.jar"},
		linkEntry{name: "opt/z-sym.jar", linkname: "real.jar"},
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

func TestIndex_collapsedLocationReadsTheTarget(t *testing.T) {
	r := indexWithLinks(t,
		linkEntry{name: "opt/real.bin", body: "PK\x03\x04 real contents"},
		linkEntry{name: "opt/a-sym.jar", linkname: "real.bin"},
		linkEntry{name: "opt/z-sym.jar", linkname: "real.bin"},
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

func TestIndex_danglingLinkHasNoContent(t *testing.T) {
	r := indexWithLinks(t, linkEntry{name: "opt/gone.jar", linkname: "missing.jar"})

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
func TestIndex_mimeTypeAnswersOnlyWithFiles(t *testing.T) {
	r := indexWithLinks(t,
		linkEntry{name: "opt/real.jar", body: "PK\x03\x04 zip contents here"},
		linkEntry{name: "opt/sym.jar", linkname: "real.jar"},
		linkEntry{name: "opt/hard.jar", linkname: "opt/real.jar", hard: true},
		linkEntry{name: "opt/gone.jar", linkname: "missing.jar"},
		linkEntry{name: "opt/notes.txt", body: "hello world"},
	)

	byMIME := func(types ...string) []string {
		t.Helper()
		locations, err := r.FilesByMIMEType(types...)
		require.NoError(t, err)
		var out []string
		for _, l := range locations {
			out = append(out, l.RealPath)
		}
		return out
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
func TestIndex_allLocationsKeepsEveryPath(t *testing.T) {
	r := indexWithLinks(t,
		linkEntry{name: "opt/real.jar", body: "PK\x03\x04"},
		linkEntry{name: "opt/sym.jar", linkname: "real.jar"},
		linkEntry{name: "opt/gone.jar", linkname: "missing.jar"},
	)

	var got []string
	for l := range r.AllLocations(context.Background()) {
		got = append(got, l.RealPath)
	}
	assert.Equal(t, []string{"opt/gone.jar", "opt/real.jar", "opt/sym.jar"}, got,
		"every path the archive names, links included")
}

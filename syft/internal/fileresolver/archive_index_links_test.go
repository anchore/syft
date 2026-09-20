package fileresolver

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/tmpdir"
)

// linkEntry is one entry of a fixture archive: a regular file when linkname is empty, otherwise a
// symlink or, with hard set, a hard link.
type linkEntry struct {
	name     string
	body     string
	linkname string
	hard     bool
}

func indexWithLinks(t testing.TB, entries ...linkEntry) *ArchiveIndex {
	t.Helper()
	workDir := archive.NewWorkDir(tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir())))
	t.Cleanup(workDir.Remove)
	store := archive.NewEntryStore(workDir, "test.tar", nil)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	charge := archive.NewLimiter(archive.Limits{MaxMemoryBytes: 1 << 20, MaxDiskBytes: -1}).Charge()

	for _, e := range entries {
		hdr := tar.Header{Name: e.name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(e.body))}
		switch {
		case e.linkname != "" && e.hard:
			hdr = tar.Header{Name: e.name, Mode: 0o644, Typeflag: tar.TypeLink, Linkname: e.linkname}
		case e.linkname != "":
			hdr = tar.Header{Name: e.name, Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: e.linkname}
		}
		_, err := store.Add(hdr, bytes.NewReader([]byte(e.body)), charge)
		require.NoError(t, err)
	}

	r, err := NewFromArchiveEntries("", "outer.tar", store, nil)
	require.NoError(t, err)
	return r
}

func globPaths(t *testing.T, r *ArchiveIndex, pattern string) []string {
	t.Helper()
	locations, err := r.FilesByGlob(pattern)
	require.NoError(t, err)
	var out []string
	for _, l := range locations {
		out = append(out, l.RealPath)
	}
	return out
}

// TestArchiveIndex_linksCollapseToOnePath covers the resolver contract that several paths to one file
// answer as one location, and which path that is.
//
// The rule is a property of the candidates, not of the order they were found in: the path that is the
// file itself wins, and otherwise the lowest-sorting one. That matters because the search accumulates
// into a map and the answer is sorted afterwards - neither of which the choice may depend on, or the
// same archive would name a different path from run to run.
func TestArchiveIndex_linksCollapseToOnePath(t *testing.T) {
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

// TestArchiveIndex_collapseIgnoresTheOrderItFinds is what holds the rule to being a rule.
//
// Sorting the answer would hide a choice made by iteration order, so this exercises the choice
// directly: the same candidates in shuffled order must always yield the same path.
func TestArchiveIndex_collapseIgnoresTheOrderItFinds(t *testing.T) {
	r := indexWithLinks(t,
		linkEntry{name: "opt/real.jar", body: "PK\x03\x04"},
		linkEntry{name: "opt/a-sym.jar", linkname: "real.jar"},
		linkEntry{name: "opt/m-sym.jar", linkname: "real.jar"},
		linkEntry{name: "opt/z-sym.jar", linkname: "real.jar"},
	)

	candidates := []*indexNode{
		r.byPath["/opt/real.jar"], r.byPath["/opt/a-sym.jar"],
		r.byPath["/opt/m-sym.jar"], r.byPath["/opt/z-sym.jar"],
	}
	for _, node := range candidates {
		require.NotNil(t, node)
	}

	rng := rand.New(rand.NewSource(1))
	for range 64 {
		rng.Shuffle(len(candidates), func(i, j int) {
			candidates[i], candidates[j] = candidates[j], candidates[i]
		})

		found := map[*indexNode]struct{}{}
		for _, node := range candidates {
			found[node] = struct{}{}
		}

		best := collapseToOnePathPerFile(found)
		require.Len(t, best, 1, "four paths, one file")
		for target, access := range best {
			assert.Equal(t, "/opt/real.jar", target.path)
			assert.Equal(t, "/opt/real.jar", access.path, "the file itself must win from any order")
		}
	}

	// and with the file itself not among the candidates, the lowest-sorting link wins from any order
	links := candidates[:0:0]
	for _, node := range candidates {
		if node.path != "/opt/real.jar" {
			links = append(links, node)
		}
	}
	for range 64 {
		rng.Shuffle(len(links), func(i, j int) { links[i], links[j] = links[j], links[i] })

		found := map[*indexNode]struct{}{}
		for _, node := range links {
			found[node] = struct{}{}
		}

		for _, access := range collapseToOnePathPerFile(found) {
			assert.Equal(t, "/opt/a-sym.jar", access.path, "the lowest-sorting link must win from any order")
		}
	}
}

// TestArchiveIndex_collapsedLocationReadsTheTarget covers what the collapsed answer is for: the
// location has to name the link a reader recognizes while reading the bytes the file actually holds.
func TestArchiveIndex_collapsedLocationReadsTheTarget(t *testing.T) {
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

// TestArchiveIndex_dangingLinkHasNoContent covers the other half of keeping a dangling link: it is
// answered as a path, and reading it fails rather than returning something invented.
func TestArchiveIndex_dangingLinkHasNoContent(t *testing.T) {
	r := indexWithLinks(t, linkEntry{name: "opt/gone.jar", linkname: "missing.jar"})

	locations, err := r.FilesByGlob("**/*.jar")
	require.NoError(t, err)
	require.Len(t, locations, 1)
	assert.Equal(t, "opt/gone.jar", locations[0].RealPath)

	reader, err := r.FileContentsByLocation(locations[0])
	if err == nil {
		t.Cleanup(func() { _ = reader.Close() })
		body, readErr := io.ReadAll(reader)
		require.NoError(t, readErr)
		assert.Empty(t, string(body), "a link to nothing holds nothing")
	}

	metadata, err := r.FileMetadataByLocation(locations[0])
	require.NoError(t, err)
	assert.Equal(t, "opt/missing.jar", metadata.LinkDestination,
		"where it pointed is still reported, resolved against the link's own directory")
}

// TestArchiveIndex_mimeTypeAnswersOnlyWithFiles covers why a link is never a MIME answer: the type is
// sniffed from content, a link has none, and the file it points at answers under its own path.
//
// Without the rule this passes by accident - a link's empty entry sniffs to no type, so no real query
// reaches one - and the accident shows through on a query for the empty type.
func TestArchiveIndex_mimeTypeAnswersOnlyWithFiles(t *testing.T) {
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

// TestArchiveIndex_allLocationsKeepsEveryPath covers the opposite rule, and why it is opposite.
//
// AllLocations is an enumeration of what the archive holds, not a search for a file. The file metadata
// cataloger reads it to record a row per path - a symlink's row being its type and where it points -
// so collapsing links here would delete the very records it exists to produce. Callers wanting only
// real files filter by type, as file.cataloger/internal.AllRegularFiles does.
func TestArchiveIndex_allLocationsKeepsEveryPath(t *testing.T) {
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

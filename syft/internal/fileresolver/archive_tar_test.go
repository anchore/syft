package fileresolver

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

// tarEntry describes one entry to write into a test tar: a symlink when link is set, a directory when
// the name ends in "/", a regular file otherwise.
type tarEntry struct {
	name string
	body string
	link string
}

// writeTestTar builds a plain tar on disk, which is what an archive's entries are overflowed into.
func writeTestTar(t *testing.T, dir string, entries ...tarEntry) string {
	t.Helper()
	path := filepath.Join(dir, "contents.tar")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	tw := tar.NewWriter(f)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body))}
		switch {
		case e.link != "":
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = e.link
			hdr.Size = 0
		case strings.HasSuffix(e.name, "/"):
			hdr.Typeflag = tar.TypeDir
		default:
			hdr.Typeflag = tar.TypeReg
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if hdr.Typeflag == tar.TypeReg {
			_, err := tw.Write([]byte(e.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	return path
}

// archiveRoot is the empty directory an archive's entries are reported relative to. Nothing is
// written into it; it exists so a path in the SBOM is relative to its own archive.
func archiveRoot(t *testing.T, dir string) string {
	t.Helper()
	root := filepath.Join(dir, "contents")
	require.NoError(t, os.MkdirAll(root, 0o755))

	// resolved, because that is the form the resolver reports paths in: it normalizes its own root
	// with EvalSymlinks, and a test comparing against the unresolved form would be comparing against
	// a path the resolver never produces - on macOS t.TempDir sits under /var, a symlink to
	// /private/var, so every prefix check here would fail on that alone
	resolved, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	return resolved
}

// locationOf finds the location the resolver reports for one path, going through AllLocations rather
// than FilesByPath: a link whose target is not in the archive resolves to nothing, and a dead link is
// exactly what some of these cases are about.
func locationOf(t *testing.T, r file.Resolver, path string) file.Location {
	t.Helper()
	// the channel is drained to the end rather than broken out of early: AllLocations runs a goroutine
	// that fills it, and abandoning it leaks that goroutine into whatever else the package tests check
	var found *file.Location
	for loc := range r.AllLocations(context.Background()) {
		if loc.RealPath == path {
			match := loc
			found = &match
		}
	}
	if found == nil {
		t.Fatalf("no location reported for %q", path)
	}
	return *found
}

// resolvedPaths is every path the resolver reports, sorted.
func resolvedPaths(t *testing.T, r file.Resolver) []string {
	t.Helper()
	var out []string
	for loc := range r.AllLocations(context.Background()) {
		out = append(out, loc.RealPath)
	}
	sort.Strings(out)
	return out
}

func TestArchiveTar_pathsAreRelativeToTheArchiveRoot(t *testing.T) {
	// the storage is an implementation detail of the scan: nothing about the tar, the offsets or the
	// scratch directory holding them may be reachable from a Location, so an SBOM produced from a
	// overflow archive says the same thing it said when the archive was expanded into a directory
	dir := t.TempDir()
	tarPath := writeTestTar(t, dir,
		tarEntry{name: "nested/marker.txt", body: "hello"},
		tarEntry{name: "top.txt", body: "top"},
	)

	r, err := NewFromArchiveTar(archiveRoot(t, dir), tarPath, "", "outer.zip")
	require.NoError(t, err)

	assert.Equal(t, []string{"nested/marker.txt", "top.txt"}, resolvedPaths(t, r))
	assert.Equal(t, 2, r.Records())
	assert.False(t, r.IndexTruncated())

	for _, path := range resolvedPaths(t, r) {
		assert.NotContains(t, path, dir, "no part of the scratch directory may reach a path")
		assert.NotContains(t, path, "contents.tar", "the storage file must not name itself in a path")
		assert.False(t, filepath.IsAbs(path), "a path inside an archive is relative to that archive")
	}

	// and the filesystem id is stamped on every location, which is what keeps identically-named files
	// in different archives apart
	locs, err := r.FilesByPath("nested/marker.txt")
	require.NoError(t, err)
	require.Len(t, locs, 1)
	assert.Equal(t, "outer.zip", locs[0].ArchivePath)

	contents, err := r.FileContentsByLocation(locs[0])
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, contents.Close()) })
	body, err := io.ReadAll(contents)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(body))
}

func TestArchiveTar_entryNamesAreSanitized(t *testing.T) {
	// nothing is written through an entry's name any more - it is a field in a tar header - so this is
	// not about arbitrary writes. It is about the path the SBOM reports: a name climbing out of the
	// archive would put a node above the archive's own root, which renders as a path outside the
	// archive and reads as a claim about the host filesystem.
	dir := t.TempDir()
	tarPath := writeTestTar(t, dir,
		tarEntry{name: "../../etc/passwd", body: "climbing"},
		tarEntry{name: "/etc/hosts", body: "absolute"},
		tarEntry{name: "a/./b/../c.txt", body: "noisy"},
		tarEntry{name: "./", body: ""},
		tarEntry{name: "ok.txt", body: "plain"},
	)

	r, err := NewFromArchiveTar(archiveRoot(t, dir), tarPath, "", "outer.zip")
	require.NoError(t, err)

	// every name lands inside the archive, and the archive's own root is not an entry in it
	assert.Equal(t, []string{"a/c.txt", "etc/hosts", "etc/passwd", "ok.txt"}, resolvedPaths(t, r))

	// the two hostile names collapse onto the same reported path, which is the residual: a misleading
	// path inside the right archive rather than an arbitrary write or a claim about the host
	byPath, err := r.FilesByPath("etc/passwd")
	require.NoError(t, err)
	require.Len(t, byPath, 1)

	contents, err := r.FileContentsByLocation(byPath[0])
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, contents.Close()) })
	body, err := io.ReadAll(contents)
	require.NoError(t, err)
	assert.Equal(t, "climbing", string(body), "the entry is still readable under its sanitized name")
}

func TestArchiveTar_linkTargetsAreResolvedInsideTheArchive(t *testing.T) {
	// a link is resolved in archive-relative space, where a climb clamps at the root, so a target
	// naming the host filesystem lands somewhere inside this archive or nowhere at all. That is
	// stronger than the check it replaces: extraction refused to CREATE such a link, and here there is
	// nothing to create.
	dir := t.TempDir()
	root := archiveRoot(t, dir)
	tarPath := writeTestTar(t, dir,
		tarEntry{name: "lib/real.txt", body: "real content"},
		tarEntry{name: "bin/link.txt", link: "../lib/real.txt"},
		tarEntry{name: "escape.txt", link: "../../../../etc/passwd"},
		tarEntry{name: "absolute.txt", link: "/etc/shadow"},
	)

	r, err := NewFromArchiveTar(root, tarPath, "", "outer.zip")
	require.NoError(t, err)

	t.Run("a legitimate relative link still resolves", func(t *testing.T) {
		locs, err := r.FilesByPath("bin/link.txt")
		require.NoError(t, err)
		require.Len(t, locs, 1)

		contents, err := r.FileContentsByLocation(locs[0])
		require.NoError(t, err)
		defer func() { require.NoError(t, contents.Close()) }()
		body, err := io.ReadAll(contents)
		require.NoError(t, err)
		assert.Equal(t, "real content", string(body), "the link must resolve to its target's content")
	})

	for _, name := range []string{"escape.txt", "absolute.txt"} {
		t.Run("a link out of the archive names nothing on the host: "+name, func(t *testing.T) {
			// it is still a file of the archive, and it resolves to nothing rather than to the host:
			// FilesByPath follows the link and finds no target
			followed, err := r.FilesByPath(name)
			require.NoError(t, err)
			assert.Empty(t, followed, "the link must resolve to nothing, not to a path on the host")

			metadata, err := r.FileMetadataByLocation(locationOf(t, r, name))
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(metadata.LinkDestination, root+"/"),
				"the target must be re-rooted inside the archive, got %q", metadata.LinkDestination)
			// the climb is clamped rather than followed: what is left of the target after the archive's
			// own root is a path inside the archive, not a path on the host
			inside := strings.TrimPrefix(metadata.LinkDestination, root+"/")
			assert.NotContains(t, inside, "..", "a climb out of the archive must be clamped, got %q", inside)
		})
	}
}

func TestArchiveTar_aTarEndingPartWayThroughAnEntryIsUsable(t *testing.T) {
	// what the disk limit stopping a copy leaves behind. Everything read before that point is intact,
	// so it is kept and the tail is reported as a truncation - discarding an archive that was
	// cataloged perfectly well up to the cut would lose more than it protects.
	dir := t.TempDir()
	tarPath := writeTestTar(t, dir,
		tarEntry{name: "first.txt", body: "first"},
		tarEntry{name: "second.txt", body: strings.Repeat("s", 2048)},
	)

	full, err := os.ReadFile(tarPath)
	require.NoError(t, err)
	cut := filepath.Join(dir, "cut.tar")
	// through the first entry and into the second's data
	require.NoError(t, os.WriteFile(cut, full[:3*512+16], 0o600))

	r, err := NewFromArchiveTar(archiveRoot(t, dir), cut, "", "outer.tar")
	require.NoError(t, err)
	assert.Equal(t, []string{"first.txt"}, resolvedPaths(t, r))
	assert.True(t, r.IndexTruncated())

	t.Run("a tar that holds nothing readable is an error, not an empty filesystem", func(t *testing.T) {
		garbage := filepath.Join(dir, "garbage.tar")
		require.NoError(t, os.WriteFile(garbage, []byte("this is not a tar at all"), 0o600))

		_, err := NewFromArchiveTar(archiveRoot(t, t.TempDir()), garbage, "", "outer.tar")
		require.Error(t, err)
	})
}

func TestArchiveTar_pathFiltersDropEntriesAndPruneDirectories(t *testing.T) {
	// an exclusion pattern reaches inside an archive by the same mechanism as before - a visitor per
	// entry as the filesystem is indexed - so an excluded entry is ABSENT from the archive's filesystem
	// rather than present and skipped. A tar is a sequence rather than a walk, so a pruned directory
	// has to be remembered and later entries checked against it.
	dir := t.TempDir()
	root := archiveRoot(t, dir)
	tarPath := writeTestTar(t, dir,
		tarEntry{name: "keep.txt", body: "keep"},
		tarEntry{name: "drop.txt", body: "drop"},
		tarEntry{name: "vendor/", body: ""},
		tarEntry{name: "vendor/deep/inner.txt", body: "inner"},
	)

	filter := func(_, path string, info os.FileInfo, _ error) error {
		switch {
		case strings.HasSuffix(path, "/drop.txt"):
			return ErrSkipPath
		case info != nil && info.IsDir() && strings.HasSuffix(path, "/vendor"):
			return filepath.SkipDir
		}
		return nil
	}

	r, err := NewFromArchiveTar(root, tarPath, "", "outer.zip", filter)
	require.NoError(t, err)

	assert.Equal(t, []string{"keep.txt"}, resolvedPaths(t, r),
		"the dropped file and everything under the pruned directory must be absent")
	assert.Equal(t, 1, r.Records(), "an excluded entry is not a record either")
}

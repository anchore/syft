package archive

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The path-safety guards are covered here directly, since extraction no longer writes a file or link
// per archive entry:
//
// resolvesInsideRoot, resolveLink and isWithin guard the one filesystem write left in this package -
// an archive's own bytes spilling into its work directory, under a name derived from where the
// archive was found, which inside another archive is attacker-supplied text.
//
// A symlink entry creates nothing on disk: it is stored as a header, and where the link points is
// decided inside the archive's own filetree.

func TestResolvesInsideRoot_multiStepSymlinkChainIsRefused(t *testing.T) {
	// the escape the guard exists for: two cooperating links each pass a lexical check and together
	// resolve above the root. "d" -> "." lands on the root, so "d/up" -> ".." becomes "<root>/up" ->
	// ".." pointing above it, and a write through "d/up/x" lands outside. A lexical check sees
	// <root>/d/../x and allows it; only resolving against the real filesystem catches it.
	base := t.TempDir()
	root := filepath.Join(base, "contents")
	require.NoError(t, os.MkdirAll(root, 0o755))

	require.NoError(t, os.Symlink(".", filepath.Join(root, "d")))
	require.NoError(t, os.Symlink("..", filepath.Join(root, "up")))

	inside, err := resolvesInsideRoot(root, filepath.Join(root, "d", "up", "PWNED"))
	require.NoError(t, err)
	assert.False(t, inside, "a write through a link chain that leaves the root must be refused")
}

func TestResolvesInsideRoot_legitimatePathsAreAllowed(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "contents")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "lib"), 0o755))

	for _, path := range []string{
		filepath.Join(root, "top.txt"),
		filepath.Join(root, "lib", "deep", "file.txt"),
	} {
		inside, err := resolvesInsideRoot(root, path)
		require.NoError(t, err)
		assert.True(t, inside, "%s is inside the root and must be allowed", path)
	}
}

func TestResolvesInsideRoot_siblingSharingThePrefixIsRefused(t *testing.T) {
	// the string-prefix hole: "contents-evil" shares "contents" as a prefix and is not inside it
	base := t.TempDir()
	root := filepath.Join(base, "contents")
	require.NoError(t, os.MkdirAll(root, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(base, "contents-evil"), 0o755))

	inside, err := resolvesInsideRoot(root, filepath.Join(base, "contents-evil", "x.txt"))
	require.NoError(t, err)
	assert.False(t, inside)
}

func TestResolvesInsideRoot_KNOWN_LIMIT_aLinkWhoseOwnTargetPathLeavesTheRoot(t *testing.T) {
	// KNOWN GAP, recorded as a finding rather than a passing assertion of safety.
	//
	// Two links then a write: "up" -> "..", then "bin/link.txt" -> "../up/PWNED", then a write to
	// "bin/link.txt/through". resolvesInsideRoot walks the write path, meets bin/link.txt, and resolves
	// its target lexically without walking the target's own path, never seeing that <root>/up is itself
	// a link out of the root. On the real filesystem the write lands above the root.
	//
	// Not a live exposure: resolvesInsideRoot's only caller writes one flat name into a work directory
	// it just created, where no link can be planted. Anything that gives it a caller over
	// archive-supplied paths must close this first.
	base := t.TempDir()
	root := filepath.Join(base, "contents")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "bin"), 0o755))
	require.NoError(t, os.Symlink("..", filepath.Join(root, "up")))
	require.NoError(t, os.Symlink("../up/PWNED", filepath.Join(root, "bin", "link.txt")))

	inside, err := resolvesInsideRoot(root, filepath.Join(root, "bin", "link.txt", "through"))
	require.NoError(t, err)
	assert.True(t, inside,
		"the guard allows this write, and the real filesystem puts it above the root - the hole this "+
			"case exists to record")
}

func TestArchiveFileName_refusesNamesThatWouldLeaveTheWorkDirectory(t *testing.T) {
	// an archive spills under the basename of where it was found, and Base returns ".." for an access
	// path ending in it, which joined to the work directory would name the directory above.
	// overflowContent checks its destination too, so this is the earlier of two refusals.
	for _, accessPath := range []string{"", ".", "..", "a/..", string(filepath.Separator)} {
		assert.Equal(t, "archive", archiveFileName(accessPath),
			"%q must not become a name joined to the work directory", accessPath)
	}

	// and a real name is preserved, compound extension included, so format detection has the best
	// chance of identifying the archive
	assert.Equal(t, "bundle.tar.gz", archiveFileName("some/path/bundle.tar.gz"))
}

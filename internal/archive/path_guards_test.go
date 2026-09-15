package archive

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The path-safety guards used to be exercised through extraction, because extraction created a file
// or a link per archive entry and every one of them went through them. An entry is a tar header now,
// so those tests assert something else and these guards need their own.
//
// They are covered here rather than retired because their situations differ:
//
//   - resolvesInsideRoot, resolveLink and isWithin guard the one filesystem write left in this
//     package - an archive's own bytes overflowing into its work directory, under a name derived from
//     where the archive was found, which inside another archive is text the archive supplied.
//   - writeSafeSymlink has no caller at all. A symlink entry is a header write, which creates
//     nothing, and where the link points is decided inside the archive's own filetree. It is kept
//     with its reasoning intact, and whether it retires is a judgement about every path that could
//     write a link rather than about one call site.

func TestResolvesInsideRoot_multiStepSymlinkChainIsRefused(t *testing.T) {
	// the escape the guard exists for: two cooperating links each pass a lexical check and together
	// resolve above the root. "d" -> "." lands on the root, so "d/up" -> ".." is created as
	// "<root>/up" -> ".." and points above it, and a write through "d/up/x" lands outside. A lexical
	// check sees <root>/d/../x and allows it; only resolving against the real filesystem catches it.
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

func TestWriteSafeSymlink(t *testing.T) {
	// asserted with no production caller, deliberately: see the note at the top of this file. The
	// reasoning in these cases is what makes the function worth keeping, so it is kept executable
	// rather than left as prose about code nothing runs.
	newRoot := func(t *testing.T) string {
		t.Helper()
		base := t.TempDir()
		root := filepath.Join(base, "contents")
		require.NoError(t, os.MkdirAll(filepath.Join(root, "bin"), 0o755))
		require.NoError(t, os.MkdirAll(filepath.Join(root, "lib"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, "lib", "real.txt"), []byte("real"), 0o600))
		return root
	}

	t.Run("a relative target inside the root is written", func(t *testing.T) {
		root := newRoot(t)
		dest := filepath.Join(root, "bin", "link.txt")
		require.NoError(t, writeSafeSymlink("../lib/real.txt", dest, root))

		body, err := os.ReadFile(dest)
		require.NoError(t, err)
		assert.Equal(t, "real", string(body))
	})

	for _, tc := range []struct {
		name   string
		target string
	}{
		{name: "an empty target", target: ""},
		{
			// os.Symlink writes the literal string, so reading the link resolves on the host whatever
			// was checked when it was created
			name:   "an absolute target",
			target: "/etc/passwd",
		},
		{name: "a target climbing out of the root", target: "../../../../etc/passwd"},
	} {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			root := newRoot(t)
			dest := filepath.Join(root, "bin", "link.txt")
			require.Error(t, writeSafeSymlink(tc.target, dest, root))

			_, err := os.Lstat(dest)
			assert.True(t, os.IsNotExist(err), "nothing may be created for a refused link")
		})
	}

	t.Run("a target that resolves out of the root through an earlier link is refused", func(t *testing.T) {
		// the target itself can run through a link an earlier entry left behind
		root := newRoot(t)
		base := filepath.Dir(root)
		require.NoError(t, os.Symlink("..", filepath.Join(root, "up")))
		require.NoError(t, os.WriteFile(filepath.Join(base, "PWNED"), []byte("x"), 0o600))

		dest := filepath.Join(root, "bin", "link.txt")
		require.Error(t, writeSafeSymlink("../up/PWNED", dest, root))

		_, err := os.Lstat(dest)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("KNOWN LIMIT: a target whose own path runs out of the root is not caught by either guard", func(t *testing.T) {
		// Recorded as a finding rather than a passing assertion of safety, because it is one.
		//
		// Three entries: "up" -> "..", then "bin/link.txt" -> "../up/PWNED", then a write to
		// "bin/link.txt/through". writeSafeSymlink computes <root>/up/PWNED, which is lexically inside
		// the root, and its last check - does the target already resolve outside? - does not fire,
		// because <root>/up/PWNED does not exist yet. So the link is created. resolvesInsideRoot then
		// walks the write path, meets bin/link.txt, and resolves its target the same lexical way: the
		// target's own path is not walked, so the fact that <root>/up is itself a link out of the root
		// is never seen, and the write is allowed. On the real filesystem it lands above the root.
		//
		// It is not a live exposure. The only caller of resolvesInsideRoot writes one flat name into a
		// work directory it just created, where no link exists and none can be planted, and
		// writeSafeSymlink has no caller at all - a symlink entry is a header write now. It matters
		// because it is what the retirement question actually hangs on: these two are not a working
		// defence being kept in reserve, they are a defence with a hole in it and no exposure, and
		// anything that gives them a caller again has to close this first.
		root := newRoot(t)
		require.NoError(t, os.Symlink("..", filepath.Join(root, "up")))

		dest := filepath.Join(root, "bin", "link.txt")
		require.NoError(t, writeSafeSymlink("../up/PWNED", dest, root),
			"the link is created: its target does not resolve outside the root YET")

		inside, err := resolvesInsideRoot(root, filepath.Join(root, "bin", "link.txt", "through"))
		require.NoError(t, err)
		assert.True(t, inside,
			"the guard allows this write, and the real filesystem puts it above the root - the hole this "+
				"case exists to record")
	})
}

func TestArchiveFileName_refusesNamesThatWouldLeaveTheWorkDirectory(t *testing.T) {
	// the name an archive's own bytes are overflowed under is the basename of where the archive was
	// found, and Base returns ".." for an access path ending in it - which joined to the work
	// directory would name the directory above. overflowContent checks its destination as well, so this
	// is the earlier of two refusals rather than the only one.
	for _, accessPath := range []string{"", ".", "..", "a/..", string(filepath.Separator)} {
		assert.Equal(t, "archive", archiveFileName(accessPath),
			"%q must not become a name joined to the work directory", accessPath)
	}

	// and a real name is preserved, compound extension included, so format detection has the best
	// chance of identifying the archive
	assert.Equal(t, "bundle.tar.gz", archiveFileName("some/path/bundle.tar.gz"))
}

package syft

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

func Test_newArchiveExclusionVisitor(t *testing.T) {
	t.Run("no patterns means no visitor", func(t *testing.T) {
		// so the archive resolver is built exactly as it was before this existed
		visitor, err := newArchiveExclusionVisitor(t.TempDir(), nil)
		require.NoError(t, err)
		assert.Nil(t, visitor)
	})

	t.Run("matching is relative to the extraction directory", func(t *testing.T) {
		// and NOT against a pattern rewritten to be absolute, which is what the directory source does
		// with the scan root. The two are only distinguishable when the temp directory holding the
		// extraction has a segment the pattern would match, which is why the check below builds one.
		root := filepath.Join(t.TempDir(), "vendor")
		require.NoError(t, os.MkdirAll(filepath.Join(root, "keep"), 0o755))

		// the paths handed to a visitor are the symlink-resolved ones the indexer walks, so the test
		// has to speak in those too: on macOS t.TempDir sits under /var, a symlink to /private/var,
		// and an unresolved path would strip no prefix and match the temp directory's own segments
		root, err := filepath.EvalSymlinks(root)
		require.NoError(t, err)

		visitor, err := newArchiveExclusionVisitor(root, []string{"**/vendor"})
		require.NoError(t, err)
		require.NotNil(t, visitor)

		assert.NoError(t, visitor("", root, dirInfo(t, root), nil),
			"the extraction directory itself is the archive, not something in it")
		assert.NoError(t, visitor("", filepath.Join(root, "keep"), dirInfo(t, filepath.Join(root, "keep")), nil),
			"a path under a matching temp directory must not inherit the match")
	})

	t.Run("a matching file is skipped and a matching directory is pruned", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "a", "vendor")
		require.NoError(t, os.MkdirAll(dir, 0o755))
		file := filepath.Join(root, "a", "pkg.rpm")
		require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

		visitor, err := newArchiveExclusionVisitor(root, []string{"**/vendor", "**/*.rpm"})
		require.NoError(t, err)
		require.NotNil(t, visitor)

		assert.ErrorIs(t, visitor("", file, fileInfo(t, file), nil), fileresolver.ErrSkipPath)
		assert.ErrorIs(t, visitor("", dir, dirInfo(t, dir), nil), filepath.SkipDir)
	})

	t.Run("an any-depth pattern reaches the archive's own root", func(t *testing.T) {
		// `**/x` matches x at zero depth as well as below it, which is what makes "exclude .rpm
		// everywhere" stop an .rpm sitting directly inside another archive
		root := t.TempDir()
		file := filepath.Join(root, "pkg.rpm")
		require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

		visitor, err := newArchiveExclusionVisitor(root, []string{"**/*.rpm"})
		require.NoError(t, err)

		assert.ErrorIs(t, visitor("", file, fileInfo(t, file), nil), fileresolver.ErrSkipPath)
	})

	t.Run("a non-matching path is kept", func(t *testing.T) {
		root := t.TempDir()
		file := filepath.Join(root, "keep.txt")
		require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

		visitor, err := newArchiveExclusionVisitor(root, []string{"**/*.rpm"})
		require.NoError(t, err)

		assert.NoError(t, visitor("", file, fileInfo(t, file), nil))
	})

	t.Run("an unresolvable directory is an error rather than a silent no-match", func(t *testing.T) {
		// the failure mode this guards against is invisible: a prefix that cannot be resolved strips
		// nothing, every pattern then matches nothing, and the scan looks like it had no exclusions
		_, err := newArchiveExclusionVisitor(filepath.Join(t.TempDir(), "does-not-exist"), []string{"**/x"})
		assert.Error(t, err)
	})
}

func Test_sourceExclusions(t *testing.T) {
	t.Run("a source publishes what it was configured with", func(t *testing.T) {
		src, err := directorysource.New(directorysource.Config{
			Path:    t.TempDir(),
			Exclude: source.ExcludeConfig{Paths: []string{"**/*.rpm", "./x"}},
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = src.Close() })

		assert.Equal(t, []string{"**/*.rpm", "./x"}, sourceExclusions(src))
	})

	t.Run("building the source's own resolver does not rewrite them", func(t *testing.T) {
		// the source rewrites exclusions to be absolute against the scan root while building its
		// resolver. If that rewriting reached the configured patterns, none would begin "**/" any
		// more and an archive's exclusions would degrade to "none configured" - which reads as a
		// feature that was never switched on rather than as a bug
		src, err := directorysource.New(directorysource.Config{
			Path:    t.TempDir(),
			Exclude: source.ExcludeConfig{Paths: []string{"**/*.rpm"}},
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = src.Close() })

		_, err = src.FileResolver(source.SquashedScope)
		require.NoError(t, err)

		assert.Equal(t, []string{"**/*.rpm"}, sourceExclusions(src))
	})

	t.Run("a source that publishes nothing excludes nothing", func(t *testing.T) {
		assert.Nil(t, sourceExclusions(source.FromDescription(source.Description{})))
	})
}

func dirInfo(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	return info
}

func fileInfo(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.False(t, info.IsDir())
	return info
}

package syft

import (
	"archive/tar"
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
	// entry paths are archive-relative, the frame the index hands every filter; nothing here is a path
	// on the host, so the fixtures are plain strings rather than files in a temp directory
	dir := entryInfo(tar.TypeDir)
	regular := entryInfo(tar.TypeReg)

	t.Run("no patterns means no visitor", func(t *testing.T) {
		// so the archive resolver is built exactly as it was before this existed
		assert.Nil(t, newArchiveExclusionVisitor(nil))
	})

	t.Run("matching is relative to the archive, not to any host path", func(t *testing.T) {
		// an archive is indexed in memory, so a pattern can only be satisfied by what the archive holds;
		// there is no scratch directory whose own segments could match
		visitor := newArchiveExclusionVisitor([]string{"**/vendor"})
		require.NotNil(t, visitor)

		assert.ErrorIs(t, visitor("/", "vendor", dir, nil), filepath.SkipDir)
		assert.NoError(t, visitor("/", "keep/vendored.txt", regular, nil),
			"a path that merely contains the word must not match")
		assert.NoError(t, visitor("/", "vendor-ish", regular, nil))
	})

	t.Run("a matching file is skipped and a matching directory is pruned", func(t *testing.T) {
		visitor := newArchiveExclusionVisitor([]string{"**/vendor", "**/*.rpm"})
		require.NotNil(t, visitor)

		assert.ErrorIs(t, visitor("/", "a/pkg.rpm", regular, nil), fileresolver.ErrSkipPath)
		assert.ErrorIs(t, visitor("/", "a/vendor", dir, nil), filepath.SkipDir)
	})

	t.Run("an any-depth pattern reaches the archive's own root", func(t *testing.T) {
		// `**/x` matches x at zero depth as well as below it, so "exclude .rpm everywhere" stops an .rpm
		// sitting directly inside another archive
		visitor := newArchiveExclusionVisitor([]string{"**/*.rpm"})
		require.NotNil(t, visitor)

		assert.ErrorIs(t, visitor("/", "pkg.rpm", regular, nil), fileresolver.ErrSkipPath)
		assert.ErrorIs(t, visitor("/", "deep/down/pkg.rpm", regular, nil), fileresolver.ErrSkipPath)
	})

	t.Run("a non-matching path is kept", func(t *testing.T) {
		visitor := newArchiveExclusionVisitor([]string{"**/*.rpm"})
		require.NotNil(t, visitor)

		assert.NoError(t, visitor("/", "keep.txt", regular, nil))
	})

	t.Run("a malformed pattern excludes nothing rather than failing the archive", func(t *testing.T) {
		visitor := newArchiveExclusionVisitor([]string{"[", "**/*.rpm"})
		require.NotNil(t, visitor)

		assert.NoError(t, visitor("/", "keep.txt", regular, nil))
		assert.ErrorIs(t, visitor("/", "pkg.rpm", regular, nil), fileresolver.ErrSkipPath)
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
		// the source rewrites exclusions absolute against the scan root while building its resolver. If that
		// reached the configured patterns, none would begin "**/" any more and an archive's exclusions would
		// silently degrade to none.
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

// entryInfo is the FileInfo an archive entry carries, which is what the index hands every filter -
// derived from the entry's header, not from anything on the filesystem.
func entryInfo(typeflag byte) os.FileInfo {
	mode := int64(0o600)
	if typeflag == tar.TypeDir {
		mode = 0o755
	}
	return (&tar.Header{Typeflag: typeflag, Mode: mode}).FileInfo()
}

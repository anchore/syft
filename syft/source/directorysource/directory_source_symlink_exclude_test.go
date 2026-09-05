package directorysource

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/internal/fileresolver"
)

func Test_DirectoryExclusionFunctions_ExcludeVsSymlinkTarget(t *testing.T) {
	// regression test for https://github.com/anchore/syft/issues/5232
	//
	// a directory excluded with --exclude is still indexed (and its contents
	// cataloged) when a symlink on an unexcluded path points into it. the
	// indexer follows symlinks by indexing the resolved target as a separate
	// root, so the excluded directory entry is never visited on that second
	// pass and the exclusion never fires.
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	writeFile := func(rel string) {
		p := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte("contents"), 0o644))
	}

	writeFile(filepath.Join("boot", "grub2", "grub.cfg"))
	writeFile(filepath.Join("keep", "file.txt"))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))

	indexAll := func(exclusion string) []string {
		visitors, err := GetDirectoryExclusionFunctions(root, []string{exclusion})
		require.NoError(t, err)

		res, err := fileresolver.NewFromDirectory(root, root, visitors...)
		require.NoError(t, err)

		var indexed []string
		for l := range res.AllLocations(context.Background()) {
			indexed = append(indexed, l.RealPath)
		}
		return indexed
	}

	// locations are reported relative to the resolver base, e.g. "/etc"
	assertNoExcludedContent := func(t *testing.T, indexed []string) {
		t.Helper()
		for _, p := range indexed {
			require.False(t, strings.HasPrefix(p, "/boot/") || p == "/boot", "path under excluded directory was indexed: %s", p)
		}
	}

	t.Run("file symlink into excluded directory", func(t *testing.T) {
		link := filepath.Join(root, "etc", "grub2.cfg")
		require.NoError(t, os.Symlink(filepath.Join("..", "boot", "grub2", "grub.cfg"), link))
		t.Cleanup(func() { require.NoError(t, os.Remove(link)) })

		indexed := indexAll("./boot")

		assertNoExcludedContent(t, indexed)
		require.NotContains(t, indexed, "/etc/grub2.cfg", "symlink pointing into an excluded directory was indexed")
		require.Contains(t, indexed, "/keep/file.txt")
	})

	t.Run("symlink chain into excluded directory", func(t *testing.T) {
		l1 := filepath.Join(root, "etc", "l1.cfg")
		l2 := filepath.Join(root, "etc", "l2.cfg")
		require.NoError(t, os.Symlink("l2.cfg", l1))
		require.NoError(t, os.Symlink(filepath.Join("..", "boot", "grub2", "grub.cfg"), l2))
		t.Cleanup(func() {
			require.NoError(t, os.Remove(l1))
			require.NoError(t, os.Remove(l2))
		})

		indexed := indexAll("./boot")

		assertNoExcludedContent(t, indexed)
		require.NotContains(t, indexed, "/etc/l1.cfg")
		require.NotContains(t, indexed, "/etc/l2.cfg")
	})

	t.Run("directory symlink into excluded directory", func(t *testing.T) {
		link := filepath.Join(root, "etc", "bootlink")
		require.NoError(t, os.Symlink(filepath.Join("..", "boot"), link))
		t.Cleanup(func() { require.NoError(t, os.Remove(link)) })

		indexed := indexAll("./boot")

		assertNoExcludedContent(t, indexed)
		require.NotContains(t, indexed, "/etc/bootlink", "symlink pointing into an excluded directory was indexed")
	})

	t.Run("symlink to excluded file", func(t *testing.T) {
		link := filepath.Join(root, "etc", "grub2.cfg")
		require.NoError(t, os.Symlink(filepath.Join("..", "boot", "grub2", "grub.cfg"), link))
		t.Cleanup(func() { require.NoError(t, os.Remove(link)) })

		indexed := indexAll("./boot/grub2/grub.cfg")

		require.NotContains(t, indexed, "/etc/grub2.cfg", "symlink pointing at an excluded file was indexed")
		require.NotContains(t, indexed, "/boot/grub2/grub.cfg")
	})

	t.Run("symlink to unexcluded path stays indexed", func(t *testing.T) {
		link := filepath.Join(root, "etc", "keep-link.txt")
		require.NoError(t, os.Symlink(filepath.Join("..", "keep", "file.txt"), link))
		t.Cleanup(func() { require.NoError(t, os.Remove(link)) })

		indexed := indexAll("./boot")

		require.Contains(t, indexed, "/etc/keep-link.txt", "symlink to an unexcluded path should be indexed")
		require.Contains(t, indexed, "/keep/file.txt")
	})

	t.Run("excluded directory itself is skipped in primary walk", func(t *testing.T) {
		indexed := indexAll("./boot")

		assertNoExcludedContent(t, indexed)
	})
}

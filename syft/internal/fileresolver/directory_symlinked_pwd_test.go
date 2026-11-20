package fileresolver

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A relative root is resolved against os.Getwd, which returns the logical $PWD. When that path goes through a
// symlink, the ancestors of the root include the symlink; indexing it must not pull in the symlink target's siblings.
func Test_RelativeRootWithSymlinkedPWD_DoesNotIndexSiblings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("relies on symlinks and a logical $PWD")
	}
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	for _, dir := range []string{"proj", "other"} {
		require.NoError(t, os.MkdirAll(filepath.Join(tmp, "physical", dir), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(tmp, "physical", dir, "pkg.lock"), []byte("x"), 0o644))
	}
	// relative symlink, as created by `ln -s physical link`
	require.NoError(t, os.Symlink("physical", filepath.Join(tmp, "link")))

	for _, root := range []string{"proj", "./proj"} {
		t.Run(root, func(t *testing.T) {
			t.Chdir(filepath.Join(tmp, "link"))

			resolver, err := NewFromDirectory(root, "")
			require.NoError(t, err)

			var found []string
			for loc := range resolver.AllLocations(context.Background()) {
				found = append(found, loc.RealPath)
			}
			require.NotEmpty(t, found)
			for _, p := range found {
				require.False(t, strings.Contains(p, "/other"), "%q should not contain %q", p, "/other")
			}
		})
	}
}

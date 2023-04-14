package golang

import (
	"io/fs"
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/require"
)

func Test_billyFSAdapter(t *testing.T) {
	r, err := git.PlainInit("test-fixtures/repo", false)

	t.Cleanup(func() {
		_ = os.RemoveAll("test-fixtures/repo/.git")
	})

	wt, err := r.Worktree()
	require.NoError(t, err)
	f := billyFSAdapter{
		fs: wt.Filesystem,
	}

	found := ""
	err = fs.WalkDir(f, ".", func(path string, d fs.DirEntry, err error) error {
		found = path
		return nil
	})
	require.NoError(t, err)

	require.Equal(t, "LICENSE", found)
}

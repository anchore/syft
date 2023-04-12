package golang

import (
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/src-d/go-git.v4"
)

func Test_BillyfsAdapter(t *testing.T) {
	r, err := git.PlainInit("test-fixtures/repo", false)

	t.Cleanup(func() {
		_ = os.RemoveAll("test-fixtures/repo/.git")
	})

	wt, err := r.Worktree()
	require.NoError(t, err)
	f := bfs{
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

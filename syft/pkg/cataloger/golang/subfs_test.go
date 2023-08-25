package golang

import (
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_NewSubFS(t *testing.T) {
	f := os.DirFS("test-fixtures/zip-fs")
	f = newSubFS(f, "github.com/someorg/somepkg@version")
	var names []string
	err := fs.WalkDir(f, ".", func(path string, d fs.DirEntry, err error) error {
		names = append(names, path)
		return nil
	})
	require.NoError(t, err)
	expected := []string{
		".",
		"a-file",
		"subdir",
		"subdir/subfile",
	}
	require.Equal(t, expected, names)
}

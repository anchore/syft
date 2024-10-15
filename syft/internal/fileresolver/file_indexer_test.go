package fileresolver

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/fs"
	"os"
	"path"
	"testing"
)

// - Verify that both the parent and the path are indexed
func Test_index(t *testing.T) {
	testPath := "test-fixtures/system_paths/target/home/place"
	indexer := newFileIndexer(testPath, "", make([]PathIndexVisitor, 0)...)
	tree, index, err := indexer.build()
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
	}{
		{
			name: "has path",
			path: "test-fixtures/system_paths/target/home/place",
		},
		{
			name: "has parent dir",
			path: "test-fixtures/system_paths/target/home",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, err := os.Stat(test.path)
			assert.NoError(t, err)

			// note: the index uses absolute paths, so assertions MUST keep this in mind
			cwd, err := os.Getwd()
			require.NoError(t, err)

			p := file.Path(path.Join(cwd, test.path))
			assert.Equal(t, true, tree.HasPath(p))
			exists, ref, err := tree.File(p)
			assert.Equal(t, true, exists)
			if assert.NoError(t, err) {
				return
			}

			entry, err := index.Get(*ref.Reference)
			require.NoError(t, err)
			assert.Equal(t, info.Mode(), entry.Mode)
		})
	}

}

// - Verify that directories are rejected
func Test_indexRejectsDirectory(t *testing.T) {
	dirPath := "test-fixtures/system_paths/target/home"
	indexer := newFileIndexer(dirPath, "", make([]PathIndexVisitor, 0)...)
	_, _, err := indexer.build()
	require.Error(t, err)
}

// - Verify ignores if filterAndIndex sets up a filter for the filepath
func Test_ignoresPathIfFiltered(t *testing.T) {
	testPath := "test-fixtures/system_paths/target/home/place"
	cwd, cwdErr := os.Getwd()
	require.NoError(t, cwdErr)
	ignorePath := path.Join(cwd, testPath)
	filterFn := func(_, path string, _ os.FileInfo, _ error) error {
		if path == ignorePath {
			return ErrSkipPath
		}

		return nil
	}
	indexer := newFileIndexer(testPath, "", filterFn)
	_, _, err := indexer.build()
	require.Error(t, err)
}

// - Verify ignores if filterAndIndex sets up a filter for the directory
func Test_ignoresPathIfParentFiltered(t *testing.T) {
	testPath := "test-fixtures/system_paths/target/home/place"
	parentPath := "test-fixtures/system_paths/target/home"

	cwd, cwdErr := os.Getwd()
	require.NoError(t, cwdErr)
	ignorePath := path.Join(cwd, parentPath)
	filterFn := func(_, path string, _ os.FileInfo, _ error) error {
		if path == ignorePath {
			return fs.SkipDir
		}

		return nil
	}
	indexer := newFileIndexer(testPath, "", filterFn)
	_, _, err := indexer.build()
	require.Error(t, err)
}

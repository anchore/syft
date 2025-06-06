package file

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/squashfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestFS(t *testing.T) filesystem.FileSystem {
	dir := t.TempDir()

	filename := "test.squashfs"
	f, err := os.Create(filepath.Join(dir, filename))
	require.NoError(t, err)

	b := file.New(f, false)
	fsys, err := squashfs.Create(b, 0, 0, 4096)
	require.NoError(t, err)

	testFiles := []struct {
		path    string
		content string
		isDir   bool
	}{
		{"/file1.txt", "content of file1", false},
		{"/file2.txt", "content of file2", false},
		{"/dir1", "", true},
		{"/dir1/subfile1.txt", "content of subfile1", false},
		{"/dir1/subfile2.txt", "content of subfile2", false},
		{"/dir1/subdir1", "", true},
		{"/dir1/subdir1/deepfile.txt", "deep content", false},
		{"/dir2", "", true},
		{"/dir2/anotherfile.txt", "another content", false},
		{"/emptydir", "", true},
	}

	for _, tf := range testFiles {
		if tf.isDir {
			err := fsys.Mkdir(tf.path)
			require.NoError(t, err)
		} else {
			f, err := fsys.OpenFile(tf.path, os.O_CREATE|os.O_RDWR)
			require.NoError(t, err)
			_, err = f.Write([]byte(tf.content))
			require.NoError(t, err)
			f.Close()
		}
	}

	return fsys
}

func TestWalkDiskDir_CompleteTraversal(t *testing.T) {
	fsys := createTestFS(t)

	var visitedPaths []string
	err := WalkDiskDir(fsys, "/", func(fsys filesystem.FileSystem, path string, d os.FileInfo, err error) error {
		require.NoError(t, err)
		visitedPaths = append(visitedPaths, path)
		return nil
	})

	require.NoError(t, err)

	expectedPaths := []string{
		"/file1.txt",
		"/file2.txt",
		"/dir1",
		"/dir1/subfile1.txt",
		"/dir1/subfile2.txt",
		"/dir1/subdir1",
		"/dir1/subdir1/deepfile.txt",
		"/dir2",
		"/dir2/anotherfile.txt",
		"/emptydir",
	}

	assert.ElementsMatch(t, expectedPaths, visitedPaths)
}

func TestWalkDiskDir_FileInfoCorrect(t *testing.T) {
	fsys := createTestFS(t)

	var fileInfos []struct {
		path  string
		isDir bool
		name  string
	}

	err := WalkDiskDir(fsys, "/", func(fsys filesystem.FileSystem, path string, d os.FileInfo, err error) error {
		require.NoError(t, err)
		require.NotNil(t, d)
		fileInfos = append(fileInfos, struct {
			path  string
			isDir bool
			name  string
		}{
			path:  path,
			isDir: d.IsDir(),
			name:  d.Name(),
		})
		return nil
	})

	require.NoError(t, err)

	for _, fi := range fileInfos {
		expectedName := filepath.Base(fi.path)
		assert.Equal(t, expectedName, fi.name)

		if fi.path == "/dir1" || fi.path == "/dir2" || fi.path == "/emptydir" || fi.path == "/dir1/subdir1" {
			assert.True(t, fi.isDir, "Expected %s to be directory", fi.path)
		} else {
			assert.False(t, fi.isDir, "Expected %s to be file", fi.path)
		}
	}
}

func TestWalkDiskDir_SkipDir(t *testing.T) {
	fsys := createTestFS(t)

	var visitedPaths []string
	err := WalkDiskDir(fsys, "/", func(fsys filesystem.FileSystem, path string, d os.FileInfo, err error) error {
		require.NoError(t, err)
		visitedPaths = append(visitedPaths, path)
		if path == "/dir1" {
			return fs.SkipDir
		}
		return nil
	})

	require.NoError(t, err)

	assert.Contains(t, visitedPaths, "/dir1")
	assert.NotContains(t, visitedPaths, "/dir1/subfile1.txt")
	assert.NotContains(t, visitedPaths, "/dir1/subfile2.txt")
	assert.NotContains(t, visitedPaths, "/dir1/subdir1")
	assert.NotContains(t, visitedPaths, "/dir1/subdir1/deepfile.txt")

	assert.Contains(t, visitedPaths, "/dir2")
	assert.Contains(t, visitedPaths, "/dir2/anotherfile.txt")
}

func TestWalkDiskDir_SkipAll(t *testing.T) {
	fsys := createTestFS(t)

	var visitedPaths []string
	err := WalkDiskDir(fsys, "/", func(fsys filesystem.FileSystem, path string, d os.FileInfo, err error) error {
		require.NoError(t, err)
		visitedPaths = append(visitedPaths, path)
		if path == "/dir1" {
			return fs.SkipAll
		}
		return nil
	})

	require.NoError(t, err)

	assert.Contains(t, visitedPaths, "/dir1")

	assert.NotContains(t, visitedPaths, "/file1.txt")
	assert.NotContains(t, visitedPaths, "/file2.txt")
	assert.NotContains(t, visitedPaths, "/dir1/subfile1.txt")
	assert.NotContains(t, visitedPaths, "/dir2")
	assert.NotContains(t, visitedPaths, "/dir2/anotherfile.txt")
	assert.NotContains(t, visitedPaths, "/emptydir")
}

func TestWalkDiskDir_EmptyDirectory(t *testing.T) {
	fs := createTestFS(t)

	var visitedPaths []string
	err := WalkDiskDir(fs, "/emptydir", func(fsys filesystem.FileSystem, path string, d os.FileInfo, err error) error {
		require.NoError(t, err)
		visitedPaths = append(visitedPaths, path)
		return nil
	})

	require.NoError(t, err)
	assert.Empty(t, visitedPaths)
}

func TestWalkDiskDir_NonexistentPath(t *testing.T) {
	fs := createTestFS(t)

	err := WalkDiskDir(fs, "/nonexistent", func(fsys filesystem.FileSystem, path string, d os.FileInfo, err error) error {
		return nil
	})

	assert.Error(t, err)
}

func TestWalkDiskDir_WalkFunctionError(t *testing.T) {
	fs := createTestFS(t)

	customErr := assert.AnError
	err := WalkDiskDir(fs, "/", func(fsys filesystem.FileSystem, path string, d os.FileInfo, err error) error {
		if path == "/file1.txt" {
			return customErr
		}
		return nil
	})

	assert.Error(t, err)
	assert.Equal(t, customErr, err)
}

func TestWalkDiskDir_SubdirectoryTraversal(t *testing.T) {
	fs := createTestFS(t)

	var visitedPaths []string
	err := WalkDiskDir(fs, "/dir1", func(fsys filesystem.FileSystem, path string, d os.FileInfo, err error) error {
		require.NoError(t, err)
		visitedPaths = append(visitedPaths, path)
		return nil
	})

	require.NoError(t, err)

	expectedPaths := []string{
		"/dir1/subfile1.txt",
		"/dir1/subfile2.txt",
		"/dir1/subdir1",
		"/dir1/subdir1/deepfile.txt",
	}

	assert.ElementsMatch(t, expectedPaths, visitedPaths)
}

func TestWalkDiskDir_SingleFile(t *testing.T) {
	fs := createTestFS(t)

	var visitedPaths []string
	err := WalkDiskDir(fs, "/file1.txt", func(fsys filesystem.FileSystem, path string, d os.FileInfo, err error) error {
		require.NoError(t, err)
		visitedPaths = append(visitedPaths, path)
		return nil
	})

	// we are providing a file path, not a directory
	require.Error(t, err)
	assert.Empty(t, visitedPaths)
}

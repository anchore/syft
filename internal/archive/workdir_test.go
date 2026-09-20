package archive

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/tmpdir"
)

func TestWorkDir_isNotCreatedUntilAskedFor(t *testing.T) {
	root := t.TempDir()
	w := NewWorkDir(tmpdir.WithValue(context.Background(), tmpdir.FromPath(root)))

	assert.False(t, w.created(), "constructing a work directory must touch nothing")
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	assert.Empty(t, entries)

	dir, err := w.Path()
	require.NoError(t, err)
	assert.DirExists(t, dir)
	assert.True(t, w.created())
}

func TestWorkDir_pathIsStableAcrossCalls(t *testing.T) {
	w := NewWorkDir(tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir())))

	first, err := w.Path()
	require.NoError(t, err)
	second, err := w.Path()
	require.NoError(t, err)
	assert.Equal(t, first, second, "the directory is created once, not once per writer")
}

func TestWorkDir_concurrentCallersShareOneDirectory(t *testing.T) {
	// the store spills under its own lock while the archive's content may be spilling too, so the
	// creation has to be safe to race
	root := t.TempDir()
	w := NewWorkDir(tmpdir.WithValue(context.Background(), tmpdir.FromPath(root)))

	var wg sync.WaitGroup
	paths := make([]string, 8)
	for i := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dir, err := w.Path()
			assert.NoError(t, err)
			paths[i] = dir
		}()
	}
	wg.Wait()

	for _, p := range paths {
		assert.Equal(t, paths[0], p)
	}
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "racing callers must not each create a directory")
}

func TestWorkDir_removeIsANoOpWhenNothingWasCreated(t *testing.T) {
	root := t.TempDir()
	w := NewWorkDir(tmpdir.WithValue(context.Background(), tmpdir.FromPath(root)))

	w.Remove()
	w.Remove()

	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestWorkDir_removeDeletesWhatWasCreated(t *testing.T) {
	w := NewWorkDir(tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir())))

	dir, err := w.Path()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "blob"), []byte("x"), 0o600))

	w.Remove()
	assert.NoDirExists(t, dir)

	// safe to call more than once, as the extraction's cleanup is
	w.Remove()
}

func TestWorkDir_nilHasNowhereToWrite(t *testing.T) {
	var w *WorkDir

	_, err := w.Path()
	assert.Error(t, err, "a caller with nowhere to put content must fail rather than pick a directory")
	assert.False(t, w.created())
	w.Remove()
}

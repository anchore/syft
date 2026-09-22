package archive

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkDir_isNotCreatedUntilAskedFor(t *testing.T) {
	ctx, root := scanContext(t)
	w := NewWorkDir(ctx)

	assert.False(t, w.wasCreated())
	assert.Empty(t, workDirsUnder(t, root))

	dir, err := w.Path()
	require.NoError(t, err)
	assert.DirExists(t, dir)
	assert.True(t, w.wasCreated())
	assert.Equal(t, []string{dir}, workDirsUnder(t, root))
}

func TestWorkDir_pathIsStableAcrossCalls(t *testing.T) {
	ctx, _ := scanContext(t)
	w := NewWorkDir(ctx)

	first, err := w.Path()
	require.NoError(t, err)
	second, err := w.Path()
	require.NoError(t, err)
	assert.Equal(t, first, second)
}

func TestWorkDir_removeIsANoOpWhenNothingWasCreated(t *testing.T) {
	ctx, root := scanContext(t)
	w := NewWorkDir(ctx)

	w.Remove()
	w.Remove()

	assert.Empty(t, workDirsUnder(t, root))
}

func TestWorkDir_removeDeletesWhatWasCreated(t *testing.T) {
	ctx, _ := scanContext(t)
	w := NewWorkDir(ctx)

	dir, err := w.Path()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "blob"), []byte("x"), 0o600))

	w.Remove()
	assert.NoDirExists(t, dir)
	w.Remove()
}

func TestWorkDir_nilHasNowhereToWrite(t *testing.T) {
	var w *WorkDir

	_, err := w.Path()
	assert.Error(t, err)
	assert.False(t, w.wasCreated())
	w.Remove()
}

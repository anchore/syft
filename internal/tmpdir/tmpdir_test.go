package tmpdir

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootAndFromContext(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, FromContext(ctx))

	ctx, td := Root(ctx, "test")
	require.NotNil(t, FromContext(ctx))
	assert.Same(t, td, FromContext(ctx))
}

func TestWithValue(t *testing.T) {
	_, td := Root(context.Background(), "test")
	defer td.Cleanup()

	// inject the existing TempDir into a fresh context
	ctx := WithValue(context.Background(), td)
	assert.Same(t, td, FromContext(ctx))

	// the injected TempDir is fully functional
	f, cleanup, err := FromContext(ctx).NewFile("with-value-*.txt")
	require.NoError(t, err)
	defer cleanup()
	require.NoError(t, f.Close())
}

func TestNewChild(t *testing.T) {
	ctx, td := Root(context.Background(), "test")
	defer td.Cleanup()
	_ = ctx

	child1, cleanup1, err := td.NewChild("sub")
	require.NoError(t, err)
	defer cleanup1()
	child2, cleanup2, err := td.NewChild("sub")
	require.NoError(t, err)
	defer cleanup2()

	// children are distinct
	assert.NotEqual(t, child1, child2)

	// both exist and are under the same root
	info1, err := os.Stat(child1)
	require.NoError(t, err)
	assert.True(t, info1.IsDir())

	info2, err := os.Stat(child2)
	require.NoError(t, err)
	assert.True(t, info2.IsDir())

	assert.Equal(t, filepath.Dir(child1), filepath.Dir(child2))
}

func TestNewFile(t *testing.T) {
	_, td := Root(context.Background(), "test")
	defer td.Cleanup()

	f, cleanup, err := td.NewFile("hello-*.txt")
	require.NoError(t, err)
	defer cleanup()

	_, err = f.WriteString("hello")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	content, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	assert.Equal(t, "hello", string(content))
}

func TestCleanup(t *testing.T) {
	_, td := Root(context.Background(), "test")

	child, _, err := td.NewChild("sub")
	require.NoError(t, err)

	f, _, err := td.NewFile("file-*")
	require.NoError(t, err)
	fname := f.Name()
	f.Close()

	// write a file inside the child dir too
	require.NoError(t, os.WriteFile(filepath.Join(child, "inner.txt"), []byte("x"), 0600))

	// everything exists
	_, err = os.Stat(child)
	require.NoError(t, err)
	_, err = os.Stat(fname)
	require.NoError(t, err)

	// cleanup
	require.NoError(t, td.Cleanup())

	// everything is gone
	_, err = os.Stat(child)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(fname)
	assert.True(t, os.IsNotExist(err))

	// double cleanup is safe
	require.NoError(t, td.Cleanup())
}

func TestCleanupPreventsNewAllocation(t *testing.T) {
	_, td := Root(context.Background(), "test")
	require.NoError(t, td.Cleanup())

	_, _, err := td.NewChild("nope")
	assert.Error(t, err)

	_, _, err = td.NewFile("nope-*")
	assert.Error(t, err)
}

func TestEarlyCleanupFile(t *testing.T) {
	_, td := Root(context.Background(), "test")
	defer td.Cleanup()

	f, cleanup, err := td.NewFile("early-*.txt")
	require.NoError(t, err)

	fname := f.Name()
	require.NoError(t, f.Close())

	// file exists before cleanup
	_, err = os.Stat(fname)
	require.NoError(t, err)

	// early cleanup removes the file
	cleanup()
	_, err = os.Stat(fname)
	assert.True(t, os.IsNotExist(err))

	// calling cleanup again is safe (idempotent)
	cleanup()
}

func TestEarlyCleanupChild(t *testing.T) {
	_, td := Root(context.Background(), "test")
	defer td.Cleanup()

	child, cleanup, err := td.NewChild("early")
	require.NoError(t, err)

	// child dir exists
	_, err = os.Stat(child)
	require.NoError(t, err)

	// early cleanup removes it
	cleanup()
	_, err = os.Stat(child)
	assert.True(t, os.IsNotExist(err))

	// calling cleanup again is safe (idempotent)
	cleanup()
}

func TestEarlyCleanupThenRootCleanup(t *testing.T) {
	_, td := Root(context.Background(), "test")

	f, cleanupFile, err := td.NewFile("combo-*.txt")
	require.NoError(t, err)
	fname := f.Name()
	f.Close()

	child, cleanupChild, err := td.NewChild("combo")
	require.NoError(t, err)

	// early cleanup both
	cleanupFile()
	cleanupChild()

	// files are already gone
	_, err = os.Stat(fname)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(child)
	assert.True(t, os.IsNotExist(err))

	// root cleanup still works (no error on already-removed contents)
	require.NoError(t, td.Cleanup())
}

func TestConcurrentNewChildAndNewFile(t *testing.T) {
	_, td := Root(context.Background(), "test")
	defer td.Cleanup()

	const goroutines = 20
	errs := make(chan error, goroutines)
	paths := make(chan string, goroutines)

	for i := range goroutines {
		go func(i int) {
			if i%2 == 0 {
				child, cleanup, err := td.NewChild("concurrent")
				if err != nil {
					errs <- err
					return
				}
				defer cleanup()
				paths <- child
			} else {
				f, cleanup, err := td.NewFile("concurrent-*.txt")
				if err != nil {
					errs <- err
					return
				}
				defer cleanup()
				_ = f.Close()
				paths <- f.Name()
			}
			errs <- nil
		}(i)
	}

	seen := make(map[string]bool)
	for range goroutines {
		err := <-errs
		require.NoError(t, err)
	}
	close(paths)
	for p := range paths {
		assert.False(t, seen[p], "duplicate path: %s", p)
		seen[p] = true
	}
	assert.Len(t, seen, goroutines)
}

func TestConcurrentNewChildDuringCleanup(t *testing.T) {
	_, td := Root(context.Background(), "test")

	// trigger root creation
	_, cleanup, err := td.NewChild("init")
	require.NoError(t, err)
	cleanup()

	// cleanup and concurrent NewChild should not panic
	done := make(chan struct{})
	go func() {
		_ = td.Cleanup()
		close(done)
	}()
	// try creating children concurrently with cleanup — should get errors, not panics
	for range 10 {
		_, c, _ := td.NewChild("race")
		if c != nil {
			c()
		}
	}
	<-done
}

func TestLazyCreation(t *testing.T) {
	_, td := Root(context.Background(), "test")

	// root dir is not created until needed
	assert.Equal(t, "", td.root)

	_, _, err := td.NewFile("trigger-*")
	require.NoError(t, err)

	assert.NotEmpty(t, td.root)

	require.NoError(t, td.Cleanup())
}

func TestFromPath(t *testing.T) {
	dir := t.TempDir()
	td := FromPath(dir)

	// can create children
	child, cleanup, err := td.NewChild("sub")
	require.NoError(t, err)
	defer cleanup()
	assert.DirExists(t, child)

	// can create files
	f, cleanupFile, err := td.NewFile("file-*.txt")
	require.NoError(t, err)
	defer cleanupFile()
	require.NoError(t, f.Close())
	assert.FileExists(t, f.Name())

	// root is the provided dir
	assert.Equal(t, dir, filepath.Dir(child))
}

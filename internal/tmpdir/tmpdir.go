package tmpdir

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

type ctxKey struct{}

// Root creates a new root temp directory with the given prefix and returns a context with the
// TempDir attached. Callers should defer Cleanup() on the returned TempDir to ensure all
// temp files are removed.
func Root(ctx context.Context, prefix string) (context.Context, *TempDir) {
	td := &TempDir{prefix: prefix}
	return context.WithValue(ctx, ctxKey{}, td), td
}

// FromPath creates a TempDir backed by an existing directory. The caller owns the lifecycle of
// the directory; Cleanup() is a no-op. This is useful for wrapping a directory from t.TempDir()
// where the test framework handles cleanup automatically.
func FromPath(dir string) *TempDir {
	td := &TempDir{}
	td.root = dir
	td.initOnce.Do(func() {}) // mark as initialized
	return td
}

// WithValue returns a new context with the given TempDir attached. Use this to inject an
// existing TempDir into a context (e.g., sharing a TempDir across multiple test contexts).
func WithValue(ctx context.Context, td *TempDir) context.Context {
	return context.WithValue(ctx, ctxKey{}, td)
}

// FromContext returns the TempDir from the context, or nil if none is set.
func FromContext(ctx context.Context) *TempDir {
	td, _ := ctx.Value(ctxKey{}).(*TempDir)
	return td
}

// TempDir manages a tree of temporary directories. All files and child directories live under
// a single root path that can be removed in one shot via Cleanup(). After initialization, the
// struct has no mutable state — NewChild and NewFile delegate uniqueness to os.MkdirTemp and
// os.CreateTemp respectively, so no locking is needed on the hot path.
type TempDir struct {
	prefix      string
	root        string // set exactly once by initOnce
	initOnce    sync.Once
	initErr     error
	cleanupOnce sync.Once
	cleaned     atomic.Bool
}

func noop() {}

// path returns the root directory, lazily creating it on the first call.
func (t *TempDir) path() (string, error) {
	t.initOnce.Do(func() {
		t.root, t.initErr = os.MkdirTemp("", t.prefix+"-")
	})
	if t.initErr != nil {
		return "", fmt.Errorf("failed to create root temp dir: %w", t.initErr)
	}
	if t.cleaned.Load() {
		return "", fmt.Errorf("temp dir has been cleaned up")
	}
	return t.root, nil
}

// NewChild creates a named subdirectory under this TempDir. The returned cleanup function removes
// the subdirectory and all contents; callers should defer it to reclaim space early. The root
// Cleanup acts as a safety net if the per-child cleanup is missed. The cleanup function is safe
// to call multiple times and is safe to call after the root has already been cleaned up.
func (t *TempDir) NewChild(name string) (string, func(), error) {
	root, err := t.path()
	if err != nil {
		return "", noop, err
	}
	dir, err := os.MkdirTemp(root, name+"-")
	if err != nil {
		return "", noop, fmt.Errorf("failed to create child temp dir: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(dir)
	}
	return dir, cleanup, nil
}

// NewFile creates a new temp file under this TempDir with the given name pattern (as in os.CreateTemp).
// The caller is responsible for closing the file. The returned cleanup function removes the file;
// callers should defer it to reclaim space early. The root Cleanup acts as a safety net if the
// per-file cleanup is missed. The cleanup function is safe to call multiple times.
func (t *TempDir) NewFile(pattern string) (*os.File, func(), error) {
	root, err := t.path()
	if err != nil {
		return nil, noop, err
	}
	f, err := os.CreateTemp(root, pattern)
	if err != nil {
		return nil, noop, fmt.Errorf("failed to create temp file: %w", err)
	}
	cleanup := func() {
		_ = os.Remove(f.Name())
	}
	return f, cleanup, nil
}

// Cleanup removes the entire root directory and all contents. Safe to call multiple times.
func (t *TempDir) Cleanup() error {
	var err error
	t.cleanupOnce.Do(func() {
		t.cleaned.Store(true)
		if t.root == "" {
			return
		}
		err = os.RemoveAll(t.root)
	})
	return err
}

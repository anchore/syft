package archive

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/tmpdir"
)

// workDirName prefixes the directory holding one archive's content and entries, so a scan's leftovers
// are recognizable. Tests that sample what is on disk match on it.
const workDirName = "syft-archive"

// WorkDir is the scratch space one archive writes into, created lazily the first time something needs
// to write - an archive's own bytes spilling out of memory, or its entries spilling into the overflow
// blob.
//
// Eager creation would put one directory on disk per archive opened, whether or not it ever wrote a
// byte; most do not, and a scan walks far more archives than it spills. So the path is asked for at
// the point of writing. A nil *WorkDir has no path and fails the write.
type WorkDir struct {
	mu sync.Mutex

	// create makes the directory and returns it with the func that removes it. Called at most once.
	create func() (string, func(), error)

	path   string
	remove func()
	err    error
	done   bool
}

// NewWorkDir returns the lazily-created work directory for one archive, rooted under the scan's temp
// root (internal/tmpdir) when the context carries one - so files land where the caller configured and
// are removed together if an archive's own cleanup is missed - otherwise the system temp dir.
func NewWorkDir(ctx context.Context) *WorkDir {
	return &WorkDir{create: func() (string, func(), error) {
		if td := tmpdir.FromContext(ctx); td != nil {
			dir, cleanup, err := td.NewChild(workDirName) //nolint:gocritic // cleanup is returned, not deferred here
			if err != nil {
				return "", nil, fmt.Errorf("unable to create temp dir for archive extraction: %w", err)
			}
			return dir, cleanup, nil
		}

		dir, err := os.MkdirTemp("", workDirName+"-")
		if err != nil {
			return "", nil, fmt.Errorf("unable to create temp dir for archive extraction: %w", err)
		}
		return dir, func() {
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				log.WithFields("dir", dir, "error", rmErr).Trace("unable to remove archive temp dir")
			}
		}, nil
	}}
}

// Path returns the directory, creating it on the first call. Later calls return the same result,
// including the same failure.
func (w *WorkDir) Path() (string, error) {
	if w == nil {
		return "", fmt.Errorf("no work directory for archive content")
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.done {
		w.path, w.remove, w.err = w.create()
		w.done = true
	}
	return w.path, w.err
}

// Remove deletes the directory and its contents, and does nothing if it was never created. Safe to
// call more than once.
func (w *WorkDir) Remove() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.remove == nil {
		return
	}
	w.remove()
	w.remove = nil
}

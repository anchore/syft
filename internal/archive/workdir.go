package archive

import (
	"context"
	"fmt"
	"os"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/tmpdir"
)

// workDirName prefixes the directory holding one archive's overflow files.
const workDirName = "syft-archive"

// WorkDir is the scratch directory one archive writes overflow into. It is created on first use, so
// an archive that stays in memory never touches the filesystem.
type WorkDir struct {
	tempDir *tmpdir.TempDir

	created bool
	path    string
	remove  func()
	err     error
}

// NewWorkDir returns a work directory under the scan's temp root when ctx carries one (see
// internal/tmpdir), otherwise under the system temp directory.
func NewWorkDir(ctx context.Context) *WorkDir {
	return &WorkDir{tempDir: tmpdir.FromContext(ctx)}
}

// Path returns the directory, creating it on the first call.
func (w *WorkDir) Path() (string, error) {
	if w == nil {
		return "", fmt.Errorf("no work directory for archive content")
	}
	if !w.created {
		w.created = true
		w.path, w.remove, w.err = w.create()
	}
	return w.path, w.err
}

func (w *WorkDir) create() (string, func(), error) {
	if w.tempDir != nil {
		dir, remove, err := w.tempDir.NewChild(workDirName) //nolint:gocritic // the cleanup is returned, not deferred
		if err != nil {
			return "", nil, fmt.Errorf("unable to create temp dir for archive extraction: %w", err)
		}
		return dir, remove, nil
	}

	dir, err := os.MkdirTemp("", workDirName+"-")
	if err != nil {
		return "", nil, fmt.Errorf("unable to create temp dir for archive extraction: %w", err)
	}
	return dir, func() {
		if err := os.RemoveAll(dir); err != nil {
			log.WithFields("dir", dir, "error", err).Trace("unable to remove archive temp dir")
		}
	}, nil
}

// Remove deletes the directory if it was created. Safe to call more than once.
func (w *WorkDir) Remove() {
	if w == nil || w.remove == nil {
		return
	}
	w.remove()
	w.remove = nil
}

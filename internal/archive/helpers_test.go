package archive

import (
	"os"
	"path/filepath"
)

// Seams the package itself does not need, kept here so no production file carries a function only
// tests call.

// WorkDirAt returns a WorkDir over a directory that already exists. Production always creates its own
// (NewWorkDir); a test lends one it can inspect afterwards, so Remove leaves it alone.
func WorkDirAt(dir string) *WorkDir {
	return &WorkDir{path: dir, done: true}
}

// heldInMemory reports the entry content this store is still holding in memory. Production never asks:
// the limiter is what bounds it, and the store charges as it goes rather than tracking a total.
func (s *EntryStore) heldInMemory() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var total int64
	for _, entry := range s.entries {
		if entry.ref.mem != nil {
			total += entry.ref.length
		}
	}
	return total
}

// created reports whether anything ever asked for the directory, and so whether there is anything to
// remove.
func (w *WorkDir) created() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.remove != nil
}

// held reports what this charge is currently holding, in memory and on disk.
func (c *Charge) held() (memory, disk int64) {
	if c == nil || c.limiter == nil {
		return 0, 0
	}
	c.limiter.mu.Lock()
	defer c.limiter.mu.Unlock()
	return c.memory, c.disk
}

// openFileContent opens an archive already on disk as Content. The caller closes it.
func openFileContent(path string) (Content, error) {
	f, err := os.Open(path)
	if err != nil {
		return Content{}, err
	}
	return Content{Name: filepath.Base(path), Reader: f, closer: f}, nil
}

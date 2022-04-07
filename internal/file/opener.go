package file

import (
	"io"
	"os"
)

// Opener is an object that stores a path to later be opened as a file.
type Opener struct {
	path string
}

// Open the stored path as a io.ReadCloser.
func (o Opener) Open() (io.ReadCloser, error) {
	return os.Open(o.path)
}

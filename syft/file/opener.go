package file

import (
	"io"
	"os"
)

// Opener is an object that stores a path to later be opened as a file.
type Opener struct {
	path string
}

func NewOpener(path string) Opener {
	return Opener{
		path: path,
	}
}

// Open the stored path as a io.ReadCloser.
func (o Opener) Open() (io.ReadCloser, error) {
	return os.Open(o.path)
}

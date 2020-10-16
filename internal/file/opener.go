package file

import (
	"io"
	"os"
)

type Opener struct {
	path string
}

func (o Opener) Open() (io.ReadCloser, error) {
	return os.Open(o.path)
}

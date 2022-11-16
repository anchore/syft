package internal

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/anchore/syft/internal/log"
)

// CloseAndLogError closes the given io.Closer and reports any errors found as a warning in the log
func CloseAndLogError(closer io.Closer, location string) {
	if err := closer.Close(); err != nil {
		log.Warnf("unable to close file for location=%q: %+v", location, err)
	}
}

type ErrPath struct {
	Context string
	Path    string
	Err     error
}

func (e ErrPath) Error() string {
	return fmt.Sprintf("%s unable to observe contents of %+v: %v", e.Context, e.Path, e.Err)
}

func IsErrPath(err error) bool {
	var pathErr ErrPath
	return errors.As(err, &pathErr)
}

func IsErrPathPermission(err error) bool {
	var pathErr ErrPath
	if errors.As(err, &pathErr) {
		return os.IsPermission(pathErr.Err)
	}
	return false
}

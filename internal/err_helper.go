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

type PathError struct {
	Path string
	Err  error
}

func (e PathError) Error() string {
	return fmt.Sprintf("unable to observe contents of %+v: %v", e.Path, e.Err)
}

func IsPathError(err error) bool {
	return errors.As(err, &PathError{})
}

func IsErrPathPermission(err error) bool {
	var pathErr *PathError
	if errors.As(err, pathErr) {
		return os.IsPermission(pathErr.Err)
	}
	return false
}

package internal

import (
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

type ErrObserve struct {
	Path string
	Err  error
}

func (e ErrObserve) Error() string {
	return fmt.Sprintf("unable to observe contents of %+v: %v", e.Path, e.Err)
}

func IsErrObserve(err error) bool {
	_, ok := err.(ErrObserve)
	return ok
}

func IsErrObservePermission(err error) bool {
	observe_err, ok := err.(ErrObserve)
	if ok {
		return os.IsPermission(observe_err.Err)
	}
	return ok
}

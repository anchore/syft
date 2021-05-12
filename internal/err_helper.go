package internal

import (
	"io"

	"github.com/anchore/syft/internal/log"
)

// CloseAndLogError closes the given io.Closer and reports any errors found as a warning in the log
func CloseAndLogError(closer io.Closer, location string) {
	if err := closer.Close(); err != nil {
		log.Warnf("unable to close file for location=%q: %+v", location, err)
	}
}

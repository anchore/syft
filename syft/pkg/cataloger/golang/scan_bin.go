//nolint
package golang

import (
	"debug/buildinfo"
	"io"
	"runtime/debug"

	macho "github.com/anchore/go-macholibre"
	"github.com/anchore/syft/internal/log"
)

// unionReader is a single interface with all reading functions used by golang bin
// cataloger.
type unionReader interface {
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Closer
}

// scanFile scans file to try to report the Go and module versions.
func scanFile(reader unionReader, filename string) ([]*debug.BuildInfo, []string) {
	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, err := getReaders(reader)
	if err != nil {
		log.Warnf("golang cataloger: opening binary: %v", err)
		return nil, nil
	}

	var builds []*debug.BuildInfo
	for _, r := range readers {
		bi, err := buildinfo.Read(r)
		if err != nil {
			log.Debugf("golang cataloger: scanning file %s: %v", filename, err)
			return nil, nil
		}
		builds = append(builds, bi)
	}

	archs := getArchs(readers, builds)

	return builds, archs
}

// getReaders extracts one or more io.ReaderAt objects representing binaries that can be processed (multiple binaries in the case for multi-architecture binaries).
func getReaders(f unionReader) ([]io.ReaderAt, error) {
	if macho.IsUniversalMachoBinary(f) {
		machoReaders, err := macho.ExtractReaders(f)
		if err != nil {
			log.Debugf("extracting readers: %v", err)
			return nil, err
		}

		var readers []io.ReaderAt
		for _, e := range machoReaders {
			readers = append(readers, e.Reader)
		}

		return readers, nil
	}

	return []io.ReaderAt{f}, nil
}

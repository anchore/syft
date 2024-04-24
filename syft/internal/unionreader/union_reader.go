package unionreader

import (
	"io"

	macho "github.com/anchore/go-macholibre"
	"github.com/anchore/syft/internal/log"
)

// UnionReader is a single interface with all reading functions needed by multi-arch binary catalogers
// cataloger.
type UnionReader interface {
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Closer
}

// GetReaders extracts one or more io.ReaderAt objects representing binaries that can be processed (multiple binaries in the case for multi-architecture binaries).
func GetReaders(f UnionReader) ([]io.ReaderAt, error) {
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

func GetUnionReader(readerCloser io.ReadCloser) (UnionReader, error) {
	reader, ok := readerCloser.(UnionReader)
	if ok {
		return reader, nil
	}
	return newLazyUnionReader(readerCloser), nil
}

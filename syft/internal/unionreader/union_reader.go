package unionreader

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/diskfs/go-diskfs/filesystem/squashfs"

	macho "github.com/anchore/go-macholibre"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
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

	// file.LocationReadCloser embeds a ReadCloser, which is likely
	// to implement UnionReader. Check whether the embedded read closer
	// implements UnionReader, and just return that if so.

	if r, ok := readerCloser.(file.LocationReadCloser); ok {
		return GetUnionReader(r.ReadCloser)
	}

	if r, ok := readerCloser.(*squashfs.File); ok {
		// seeking is implemented, but not io.ReaderAt. Lets wrap it to prevent from degrading performance
		// by copying all data.
		return newReaderAtAdapter(r), nil
	}

	b, err := io.ReadAll(readerCloser)
	if err != nil {
		return nil, fmt.Errorf("unable to read contents from binary: %w", err)
	}

	bytesReader := bytes.NewReader(b)

	reader = struct {
		io.ReadCloser
		io.ReaderAt
		io.Seeker
	}{
		ReadCloser: io.NopCloser(bytesReader),
		ReaderAt:   bytesReader,
		Seeker:     bytesReader,
	}

	return reader, nil
}

type readerAtAdapter struct {
	io.ReadSeekCloser
	mu *sync.Mutex
}

func newReaderAtAdapter(rs io.ReadSeekCloser) UnionReader {
	return &readerAtAdapter{
		ReadSeekCloser: rs,
		mu:             &sync.Mutex{},
	}
}

func (r *readerAtAdapter) ReadAt(p []byte, off int64) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	currentPos, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}

	_, err = r.Seek(off, io.SeekStart)
	if err != nil {
		return 0, err
	}

	n, err = r.Read(p)

	// restore original position
	// we do this even if Read failed to maintain ReaderAt semantics
	if restoreErr := r.restorePosition(currentPos); restoreErr != nil {
		// if we can't restore position and Read succeeded, return the restore error
		// if Read already failed, keep the original error
		if err == nil {
			err = restoreErr
		}
	}

	return n, err
}

func (r *readerAtAdapter) restorePosition(pos int64) error {
	_, err := r.Seek(pos, io.SeekStart)
	return err
}

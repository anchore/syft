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

func (r *readerAtAdapter) Read(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ReadSeekCloser.Read(p)
}

func (r *readerAtAdapter) Seek(offset int64, whence int) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ReadSeekCloser.Seek(offset, whence)
}

func (r *readerAtAdapter) ReadAt(p []byte, off int64) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	currentPos, err := r.ReadSeekCloser.Seek(0, io.SeekCurrent) // save current pos
	if err != nil {
		return 0, err
	}

	_, err = r.ReadSeekCloser.Seek(off, io.SeekStart) // seek to absolute position `off`
	if err != nil {
		return 0, err
	}

	n, err = r.ReadSeekCloser.Read(p) // read from that absolute position

	// restore the position for the stateful read/seek operations
	if restoreErr := r.restorePosition(currentPos); restoreErr != nil {
		if err == nil {
			err = restoreErr
		}
	}

	return n, err
}

func (r *readerAtAdapter) restorePosition(pos int64) error {
	_, err := r.ReadSeekCloser.Seek(pos, io.SeekStart)
	return err
}

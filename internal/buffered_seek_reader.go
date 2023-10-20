package internal

import (
	"bytes"
	"errors"
	"io"

	"github.com/anchore/syft/internal/log"
)

var _ io.ReadSeekCloser = (*bufferedSeekReader)(nil)

// bufferedSeekReader wraps an io.ReadCloser to provide io.Seeker functionality.
// It only supports seeking from the start and cannot seek past what has already been read.
type bufferedSeekReader struct {
	r      io.ReadCloser
	buf    *bytes.Reader
	data   []byte
	pos    int64
	closed bool
}

func NewBufferedSeeker(rc io.ReadCloser) io.ReadSeekCloser {
	return &bufferedSeekReader{
		r: rc,
	}
}

func (bs *bufferedSeekReader) Read(p []byte) (int, error) {
	if bs.closed {
		return 0, errors.New("cannot read from closed reader")
	}
	if bs.pos == int64(len(bs.data)) {
		// if we're at the end of our buffer, read more data into it
		tmp := make([]byte, len(p))

		n, err := bs.r.Read(tmp)
		if err != nil && err != io.EOF {
			return 0, err
		} else if err == io.EOF {
			bs.closed = true
		}
		bs.data = append(bs.data, tmp[:n]...)
		bs.buf = bytes.NewReader(bs.data)
	}

	n, err := bs.buf.ReadAt(p, bs.pos)
	if err != nil && err != io.EOF {
		log.WithFields("error", err).Trace("buffered seek reader failed to read from underlying reader")
	}
	bs.pos += int64(n)

	return n, nil
}

func (bs *bufferedSeekReader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = bs.pos + offset
	case io.SeekEnd:
		return 0, errors.New("'SeekEnd' not supported")
	default:
		return 0, errors.New("invalid seek option")
	}

	if abs < 0 {
		return 0, errors.New("unable to seek before start")
	}

	if abs > int64(len(bs.data)) {
		return 0, errors.New("unable to seek past read data")
	}

	bs.pos = abs
	return bs.pos, nil
}

func (bs *bufferedSeekReader) Close() error {
	bs.closed = true
	return bs.r.Close()
}

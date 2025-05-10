package stream

import (
	"bytes"
	"fmt"
	"io"
)

// SeekableReader takes an io.Reader and returns an io.ReadSeeker relative to the current position of the reader.
// Users of this function expect to be able to reset the reader to the current position, not potentially reset the
// reader prior to the location when this reader is provided. An example is a reader with multiple JSON
// documents separated by newlines (JSONL). After reading the first document, if a call is made to decode
// the second and Seek(0, SeekStart) is called it would reset the overall reader back to the first document.
func SeekableReader(reader io.Reader) (io.ReadSeeker, error) {
	if reader == nil {
		return nil, fmt.Errorf("no bytes provided")
	}

	if r, ok := reader.(io.ReadSeeker); ok {
		return getOffsetReadSeeker(r)
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(content), nil
}

type offsetReadSeeker struct {
	rdr    io.ReadSeeker
	offset int64
}

// getOffsetReadSeeker returns a new io.ReadSeeker that may wrap another io.ReadSeeker with the current offset, so
// seek calls will be relative to the _current_ position, rather than relative to the reader itself
func getOffsetReadSeeker(r io.ReadSeeker) (io.ReadSeeker, error) {
	if r == nil {
		return nil, fmt.Errorf("no reader provided")
	}
	pos, err := r.Seek(0, io.SeekCurrent)
	if pos == 0 {
		// if the ReadSeeker is currently at 0, we don't need to track an offset
		return r, nil
	}
	return &offsetReadSeeker{
		rdr:    r,
		offset: pos,
	}, err
}

func (o *offsetReadSeeker) Read(p []byte) (n int, err error) {
	return o.rdr.Read(p)
}

func (o *offsetReadSeeker) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		if offset < 0 {
			return 0, fmt.Errorf("cannot seek < 0")
		}
		newOffset, err := o.rdr.Seek(o.offset+offset, io.SeekStart)
		return newOffset - o.offset, err
	case io.SeekCurrent:
		currentOffset, err := o.rdr.Seek(0, io.SeekCurrent)
		if err != nil {
			return 0, fmt.Errorf("cannot seek current: %w", err)
		}
		if currentOffset-o.offset+offset < 0 {
			return 0, fmt.Errorf("cannot seek < 0")
		}
		newOffset, err := o.rdr.Seek(offset, io.SeekCurrent)
		return newOffset - o.offset, err
	}
	return 0, fmt.Errorf("only SeekStart and SeekCurrent supported")
}

var _ io.ReadSeeker = (*offsetReadSeeker)(nil)

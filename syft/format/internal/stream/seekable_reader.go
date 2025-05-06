package stream

import (
	"bytes"
	"fmt"
	"io"
)

func SeekableReader(reader io.Reader) (io.ReadSeeker, error) {
	if reader == nil {
		return nil, fmt.Errorf("no bytes provided")
	}

	if r, ok := reader.(io.ReadSeeker); ok {
		return newOffsetReadSeeker(r)
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

func newOffsetReadSeeker(r io.ReadSeeker) (io.ReadSeeker, error) {
	if r == nil {
		return nil, fmt.Errorf("no reader provided")
	}
	pos, err := r.Seek(0, io.SeekCurrent)
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

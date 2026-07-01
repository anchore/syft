package stream

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// SeekableReader takes an io.Reader and returns an io.ReadSeeker relative to the current position of the reader.
// Users of this function expect to be able to reset the reader to the current position, not potentially reset the
// reader prior to the location when this reader is provided. An example is a reader with multiple JSON
// documents separated by newlines (JSONL). After reading the first document, if a call is made to decode
// the second and Seek(0, SeekStart) is called it would reset the overall reader back to the first document.
//
// If the input begins with a UTF-8, UTF-16LE, or UTF-16BE byte order mark, the content is transcoded to UTF-8
// before being returned. This lets format identifiers always operate on UTF-8 regardless of how the SBOM was
// produced (notably, PowerShell's `>` operator emits UTF-16LE on Windows).
func SeekableReader(reader io.Reader) (io.ReadSeeker, error) {
	if reader == nil {
		return nil, fmt.Errorf("no bytes provided")
	}

	head, rest, err := peekHead(reader, 3)
	if err != nil {
		return nil, err
	}

	if hasBOM(head) {
		decoded, err := io.ReadAll(transform.NewReader(rest, unicode.BOMOverride(unicode.UTF8.NewDecoder()))) //nolint:gocritic // buffering normalized content to make it seekable
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(decoded), nil
	}

	if r, ok := rest.(io.ReadSeeker); ok {
		return getOffsetReadSeeker(r)
	}

	content, err := io.ReadAll(rest) //nolint:gocritic // buffering non-seekable to seekable reader
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(content), nil
}

// peekHead returns up to n bytes from the start of r along with a reader that yields the original stream
// contents starting from the same position (the peeked bytes are not consumed). For an io.ReadSeeker we
// read then seek back; otherwise we wrap in a bufio.Reader and Peek.
func peekHead(r io.Reader, n int) ([]byte, io.Reader, error) {
	if rs, ok := r.(io.ReadSeeker); ok {
		buf := make([]byte, n)
		start, err := rs.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, nil, err
		}
		read, err := io.ReadFull(rs, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, nil, err
		}
		if _, err := rs.Seek(start, io.SeekStart); err != nil {
			return nil, nil, err
		}
		return buf[:read], rs, nil
	}

	br := bufio.NewReader(r)
	head, _ := br.Peek(n) // may return fewer than n bytes on short input; that's fine
	return head, br, nil
}

// hasBOM reports whether the given bytes begin with a UTF-8, UTF-16LE, or UTF-16BE byte order mark.
func hasBOM(head []byte) bool {
	switch {
	case len(head) >= 3 && head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF:
		return true
	case len(head) >= 2 && head[0] == 0xFF && head[1] == 0xFE:
		return true
	case len(head) >= 2 && head[0] == 0xFE && head[1] == 0xFF:
		return true
	}
	return false
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

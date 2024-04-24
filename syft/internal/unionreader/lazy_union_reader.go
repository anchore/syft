package unionreader

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

const readSize int64 = 1024 * 1024

// lazyUnionReader must implement UnionReader
var _ UnionReader = (*lazyUnionReader)(nil)

// lazyUnionReader wraps an io.Reader to make it into a logical ReadSeeker
// The reader maintains a []byte, which is everything that has been read so far.
// Otherwise, callers needing a ReadSeeker might copy the entire reader into
// a buffer in order to have a seeker.
type lazyUnionReader struct {
	buf    []byte        // the bytes that have been read so far
	cursor int64         // the current position where Read() will take place
	done   bool          // whether we have seen EOF from rc
	rc     io.ReadCloser // the underlying reader
	mu     sync.Mutex    // exported methods must acquire this lock before changing any field. Unexported methods assume their caller acquired the lock
}

func (c *lazyUnionReader) Read(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	needBytes := int64(len(p))
	newOffset := c.cursor + needBytes
	err = c.ensureReadUntil(newOffset)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	// stop reading either at cursor + length p, or the end of the buffer, whichever is sooner
	end := min(c.cursor+int64(len(p)), int64(len(c.buf)))
	copy(p, c.buf[c.cursor:end])
	n = int(end - c.cursor)
	c.cursor = end
	return n, err
}

func (c *lazyUnionReader) ReadAt(p []byte, off int64) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	needUntil := int64(len(p)) + off
	err = c.ensureReadUntil(needUntil)
	end := min(off+int64(len(p)), int64(len(c.buf)))
	start := min(off, c.maxRead())
	if off > start {
		return 0, io.EOF
	}
	copy(p, c.buf[start:end])
	return int(end - start), err
}

func (c *lazyUnionReader) Seek(offset int64, whence int) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var trueOffset int64
	var err error
	switch whence {
	case io.SeekStart:
		trueOffset = offset
	case io.SeekCurrent:
		trueOffset = offset + c.cursor
		err = c.ensureReadUntil(trueOffset)
	case io.SeekEnd:
		err = c.readAll()
		trueOffset = c.maxRead() + offset
	}
	if err != nil {
		return 0, err
	}
	if trueOffset < 0 {
		return 0, fmt.Errorf("request to read negative offset impossible %v", trueOffset)
	}
	trueOffset = min(c.maxRead(), trueOffset)
	c.cursor = trueOffset
	return c.cursor, nil
}

func (c *lazyUnionReader) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rc.Close()
}

func (c *lazyUnionReader) readAll() error {
	buf, err := io.ReadAll(c.rc)
	switch {
	case err != nil && errors.Is(err, io.EOF):
		err = nil
	case err != nil:
		return err
	}
	//c.maxRead = c.maxRead() + int64(len(buf))
	c.buf = append(c.buf, buf...)
	return nil
}

func (c *lazyUnionReader) ensureReadUntil(offset int64) error {
	readN := offset - c.maxRead()
	if readN <= 0 {
		return nil
	}
	var buf bytes.Buffer
	_, err := io.CopyN(&buf, c.rc, readN)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	c.buf = append(c.buf, buf.Bytes()...)
	return err
}

func (c *lazyUnionReader) maxRead() int64 {
	return int64(len(c.buf))
}

func max(ints ...int64) int64 {
	var maxSeen int64
	for _, in := range ints {
		if in > maxSeen {
			maxSeen = in
		}
	}
	return maxSeen
}

func min(ints ...int64) int64 {
	minSeeen := int64(math.MaxInt64) // really? math.MaxInt64 has type int?
	for _, n := range ints {
		if n < minSeeen {
			minSeeen = n
		}
	}
	return minSeeen
}

func newLazyUnionReader(readCloser io.ReadCloser) (UnionReader, error) {
	return &lazyUnionReader{
		rc: readCloser,
		mu: sync.Mutex{},
	}, nil
}

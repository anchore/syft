package unionreader

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func Test_getUnionReader_notUnionReader(t *testing.T) {
	expectedContents := "this is a test"
	reader := io.NopCloser(strings.NewReader(expectedContents))

	// make certain that the test fixture does not implement the union reader
	_, ok := reader.(UnionReader)
	require.False(t, ok)

	actual, err := GetUnionReader(reader)
	require.NoError(t, err)

	_, ok = actual.(UnionReader)
	require.True(t, ok)

	b, err := io.ReadAll(actual)
	require.NoError(t, err)

	assert.Equal(t, expectedContents, string(b))
}

type panickingUnionReader struct{}

func (p2 *panickingUnionReader) ReadAt(p []byte, off int64) (n int, err error) {
	panic("don't call this in your unit test!")
}

func (p2 *panickingUnionReader) Seek(offset int64, whence int) (int64, error) {
	panic("don't call this in your unit test!")
}

func (p2 *panickingUnionReader) Read(p []byte) (n int, err error) {
	panic("don't call this in your unit test!")
}

func (p2 *panickingUnionReader) Close() error {
	panic("don't call this in your unit test!")
}

var _ UnionReader = (*panickingUnionReader)(nil)

func Test_getUnionReader_fileLocationReadCloser(t *testing.T) {
	// panickingUnionReader is a UnionReader
	p := &panickingUnionReader{}
	embedsUnionReader := file.NewLocationReadCloser(file.Location{}, p)

	// embedded union reader is returned without "ReadAll" invocation
	ur, err := GetUnionReader(embedsUnionReader)
	require.NoError(t, err)
	require.Equal(t, p, ur)
}

func TestReaderAtAdapter_ReadAt(t *testing.T) {
	testData := "Hello, World! This is a test string for ReadAt."

	t.Run("basic functionality", func(t *testing.T) {
		reader := newReadSeekCloser(strings.NewReader(testData))
		adapter := newReaderAtAdapter(reader)

		tests := []struct {
			name     string
			offset   int64
			length   int
			expected string
		}{
			{name: "read from beginning", offset: 0, length: 5, expected: "Hello"},
			{name: "read from middle", offset: 7, length: 5, expected: "World"},
			{name: "read from end", offset: int64(len(testData) - 4), length: 4, expected: "dAt."},
			{name: "read single character", offset: 12, length: 1, expected: "!"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				buf := make([]byte, tt.length)
				n, err := adapter.ReadAt(buf, tt.offset)

				if err != nil && err != io.EOF {
					t.Fatalf("Unexpected error: %v", err)
				}

				result := string(buf[:n])
				if result != tt.expected {
					t.Errorf("Expected %q, got %q", tt.expected, result)
				}
			})
		}
	})

	t.Run("edge cases", func(t *testing.T) {
		tests := []struct {
			name        string
			data        string
			offset      int64
			bufSize     int
			expectedN   int
			expectedErr error
			expectedStr string
		}{
			{
				name:        "beyond EOF",
				data:        "Hello",
				offset:      10,
				bufSize:     5,
				expectedN:   0,
				expectedErr: io.EOF,
				expectedStr: "",
			},
			{
				// io.ReaderAt requires a non-nil error whenever it returns fewer than len(p) bytes, so a
				// buffer that runs off the end of the file reports io.EOF alongside what it did read
				name:        "partial read",
				data:        "Hello",
				offset:      2,
				bufSize:     10,
				expectedN:   3,
				expectedErr: io.EOF,
				expectedStr: "llo",
			},
			{
				name:        "empty buffer",
				data:        "Hello",
				offset:      0,
				bufSize:     0,
				expectedN:   0,
				expectedErr: nil,
				expectedStr: "",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				reader := newReadSeekCloser(strings.NewReader(tt.data))
				adapter := newReaderAtAdapter(reader)

				buf := make([]byte, tt.bufSize)
				n, err := adapter.ReadAt(buf, tt.offset)

				if err != tt.expectedErr {
					t.Errorf("Expected error %v, got %v", tt.expectedErr, err)
				}

				if n != tt.expectedN {
					t.Errorf("Expected %d bytes read, got %d", tt.expectedN, n)
				}

				result := string(buf[:n])
				if result != tt.expectedStr {
					t.Errorf("Expected %q, got %q", tt.expectedStr, result)
				}
			})
		}
	})

	t.Run("multiple reads from same position", func(t *testing.T) {
		reader := newReadSeekCloser(strings.NewReader(testData))
		adapter := newReaderAtAdapter(reader)

		// read the same data multiple times
		for i := range 3 {
			buf := make([]byte, 5)
			n, err := adapter.ReadAt(buf, 7)

			if err != nil && err != io.EOF {
				t.Fatalf("ReadAt %d failed: %v", i, err)
			}

			result := string(buf[:n])
			if result != "World" {
				t.Errorf("ReadAt %d: expected 'World', got %q", i, result)
			}
		}
	})

	t.Run("concurrent access", func(t *testing.T) {
		td := "0123456789abcdefghijklmnopqrstuvwxyz"
		reader := newReadSeekCloser(strings.NewReader(td))
		adapter := newReaderAtAdapter(reader)

		const numGoroutines = 10
		const numReads = 100

		var wg sync.WaitGroup
		results := make(chan bool, numGoroutines*numReads)

		for i := range numGoroutines {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()

				for range numReads {
					offset := int64(goroutineID % len(td))
					buf := make([]byte, 1)

					n, err := adapter.ReadAt(buf, offset)
					if err != nil && err != io.EOF {
						results <- false
						return
					}

					if n > 0 {
						expected := td[offset]
						if buf[0] != expected {
							results <- false
							return
						}
					}
					results <- true
				}
			}(i)
		}

		wg.Wait()
		close(results)

		successCount := 0
		totalCount := 0
		for success := range results {
			totalCount++
			if success {
				successCount++
			}
		}

		if successCount != totalCount {
			t.Errorf("Concurrent reads failed: %d/%d successful", successCount, totalCount)
		}
	})
}

func TestReaderAtAdapter_PositionHandling(t *testing.T) {
	testData := "Hello, World!"

	t.Run("preserves position after ReadAt", func(t *testing.T) {
		reader := newReadSeekCloser(strings.NewReader(testData))
		adapter := newReaderAtAdapter(reader)

		// move to a specific position
		initialPos := int64(7)
		_, err := adapter.Seek(initialPos, io.SeekStart)
		if err != nil {
			t.Fatalf("Failed to seek: %v", err)
		}

		// read using ReadAt
		buf := make([]byte, 5)
		_, err = adapter.ReadAt(buf, 0)
		if err != nil && err != io.EOF {
			t.Fatalf("ReadAt failed: %v", err)
		}

		// verify position is preserved
		currentPos, err := adapter.Seek(0, io.SeekCurrent)
		if err != nil {
			t.Fatalf("Failed to get current position: %v", err)
		}

		if currentPos != initialPos {
			t.Errorf("Position not preserved. Expected %d, got %d", initialPos, currentPos)
		}
	})

	t.Run("does not affect regular reads", func(t *testing.T) {
		reader := newReadSeekCloser(strings.NewReader(testData))
		adapter := newReaderAtAdapter(reader)

		// read first few bytes normally
		normalBuf := make([]byte, 5)
		n, err := adapter.Read(normalBuf)
		if err != nil {
			t.Fatalf("Normal read failed: %v", err)
		}
		if string(normalBuf[:n]) != "Hello" {
			t.Errorf("Expected 'Hello', got %q", string(normalBuf[:n]))
		}

		// use ReadAt to read from a different position
		readAtBuf := make([]byte, 5)
		n, err = adapter.ReadAt(readAtBuf, 7)
		if err != nil && err != io.EOF {
			t.Fatalf("ReadAt failed: %v", err)
		}
		if string(readAtBuf[:n]) != "World" {
			t.Errorf("Expected 'World', got %q", string(readAtBuf[:n]))
		}

		// continue normal reading - should pick up where we left off
		continueBuf := make([]byte, 2)
		n, err = adapter.Read(continueBuf)
		if err != nil {
			t.Fatalf("Continue read failed: %v", err)
		}
		if string(continueBuf[:n]) != ", " {
			t.Errorf("Expected ', ', got %q", string(continueBuf[:n]))
		}
	})
}

func TestReaderAtAdapter_Close(t *testing.T) {
	reader := newReadSeekCloser(bytes.NewReader([]byte("test data")))
	adapter := newReaderAtAdapter(reader)

	// test that adapter can be closed
	err := adapter.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	if !reader.closed {
		t.Error("Underlying reader was not closed")
	}
}

type readSeekCloser struct {
	io.ReadSeeker
	closed bool
}

func newReadSeekCloser(rs io.ReadSeeker) *readSeekCloser {
	return &readSeekCloser{ReadSeeker: rs}
}

func (r *readSeekCloser) Close() error {
	r.closed = true
	return nil
}

// scriptedReadSeeker replays a fixed sequence of Read results so tests can express the read shapes a
// squashfs-backed reader actually produces, none of which an io.ReaderAt may pass through to callers:
// a short count with a nil error, a full count paired with io.EOF, or a failure partway through a buffer.
type scriptedReadSeeker struct {
	reads  []scriptedRead
	next   int
	offset int64
}

type scriptedRead struct {
	data string
	err  error
}

func (r *scriptedReadSeeker) Read(p []byte) (int, error) {
	if r.next >= len(r.reads) {
		return 0, io.EOF
	}
	read := r.reads[r.next]
	r.next++
	n := copy(p, read.data)
	r.offset += int64(n)
	return n, read.err
}

func (r *scriptedReadSeeker) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekCurrent {
		return r.offset, nil
	}
	r.offset = offset
	return offset, nil
}

func (r *scriptedReadSeeker) Close() error { return nil }

func TestReaderAtAdapter_ReadAtHonorsReaderAtContract(t *testing.T) {
	errBoom := errors.New("boom")

	tests := []struct {
		name        string
		reads       []scriptedRead
		bufSize     int
		expectedN   int
		expectedErr error
		expectedStr string
	}{
		{
			// before io.ReadFull the caller got the first 3 bytes and a nil error, and any parser sizing a
			// struct off the result read zero padding it had no way to detect
			name:        "fills the buffer across short reads",
			reads:       []scriptedRead{{data: "abc"}, {data: "def"}, {data: "ghi"}},
			bufSize:     9,
			expectedN:   9,
			expectedErr: nil,
			expectedStr: "abcdefghi",
		},
		{
			// squashfs pairs io.EOF with a full buffer when a read lands exactly on the end of the file;
			// bytes.Reader.ReadAt returns nil there, and callers that treat any error as fatal rely on it
			name:        "drops io.EOF when the read still filled the buffer",
			reads:       []scriptedRead{{data: "abc"}, {data: "def", err: io.EOF}},
			bufSize:     6,
			expectedN:   6,
			expectedErr: nil,
			expectedStr: "abcdef",
		},
		{
			// a short tail must surface as io.EOF rather than io.ErrUnexpectedEOF so callers comparing
			// against io.EOF keep working
			name:        "reports a short tail as io.EOF",
			reads:       []scriptedRead{{data: "abc"}, {data: "de", err: io.EOF}},
			bufSize:     10,
			expectedN:   5,
			expectedErr: io.EOF,
			expectedStr: "abcde",
		},
		{
			// the io.ErrUnexpectedEOF remap must not swallow a real read failure, and the byte count has to
			// survive it, otherwise callers cannot tell how much of the buffer is trustworthy
			name:        "propagates a failure partway through the buffer",
			reads:       []scriptedRead{{data: "abc"}, {data: "", err: errBoom}},
			bufSize:     10,
			expectedN:   3,
			expectedErr: errBoom,
			expectedStr: "abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &scriptedReadSeeker{reads: tt.reads}
			adapter := newReaderAtAdapter(reader)

			buf := make([]byte, tt.bufSize)
			n, err := adapter.ReadAt(buf, 7)

			require.ErrorIs(t, err, tt.expectedErr)
			assert.Equal(t, tt.expectedN, n)
			assert.Equal(t, tt.expectedStr, string(buf[:n]))

			// the position must be restored even though the read spanned multiple underlying calls
			pos, err := adapter.Seek(0, io.SeekCurrent)
			require.NoError(t, err)
			assert.Zero(t, pos)
		})
	}
}

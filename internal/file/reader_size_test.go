package file

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReaderSize(t *testing.T) {
	tests := []struct {
		name   string
		r      io.ReaderAt
		want   int64
		wantOK bool
	}{
		{
			name:   "bytes.Reader answers directly",
			r:      bytes.NewReader(make([]byte, 1234)),
			want:   1234,
			wantOK: true,
		},
		{
			// an empty reader is not a size to bound against, so it reports not-ok along with everything
			// else that cannot be measured
			name: "empty bytes.Reader",
			r:    bytes.NewReader(nil),
			want: 0,
		},
		{
			name:   "SectionReader over a real length",
			r:      io.NewSectionReader(bytes.NewReader(make([]byte, 500)), 100, 300),
			want:   300,
			wantOK: true,
		},
		{
			name:   "seek-only reader falls back to seeking",
			r:      seekOnly{bytes.NewReader(make([]byte, 4096))},
			want:   4096,
			wantOK: true,
		},
		{
			name: "reader with neither Size nor Seek cannot be measured",
			r:    readAtOnly{bytes.NewReader(make([]byte, 4096))},
			want: 0,
		},
		{
			// the shape debug/elf, debug/pe and debug/macho build internally. Taking this at its word hands
			// back a bound that permits everything, reported as if it had been measured.
			name: "SectionReader over a nominal length reports what it can deliver",
			r:    io.NewSectionReader(bytes.NewReader(make([]byte, 500)), 0, 1<<63-1),
			want: 0,
		},
		{
			// a Size() a type simply got wrong is the same failure: the bytes are what decides
			name: "a size the reader cannot back up is refused",
			r:    overstatedSize{ReaderAt: bytes.NewReader(make([]byte, 10)), size: 1 << 30},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, ok := ReaderSize(tt.r)
			assert.Equal(t, tt.want, size)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}

func TestReaderSize_FileHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.bin")
	require.NoError(t, os.WriteFile(path, make([]byte, 7777), 0o600))
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	// the cursor has to come back where it was found: the caller may be mid-read, and an *os.File is the
	// one input here that carries a shared position
	_, err = f.Seek(101, io.SeekStart)
	require.NoError(t, err)

	size, ok := ReaderSize(f)
	assert.True(t, ok)
	assert.Equal(t, int64(7777), size)

	at, err := f.Seek(0, io.SeekCurrent)
	require.NoError(t, err)
	assert.Equal(t, int64(101), at, "measuring the file must not move the caller's cursor")
}

// TestReaderSize_WrapperMustForwardSize pins the shape that made every bound expressed against this
// helper go silently inert. A type that embeds io.ReaderAt as an interface promotes only ReadAt, so it
// answers 0 here however sizable the reader underneath is, and a caller that treats 0 as "fall back to
// unbounded" then stops bounding anything. Forwarding Size() is what fixes it, and this is the assertion
// that a new wrapper has to satisfy.
func TestReaderSize_WrapperMustForwardSize(t *testing.T) {
	inner := bytes.NewReader(make([]byte, 2048))

	size, ok := ReaderSize(embedsReaderAt{inner})
	assert.False(t, ok, "a wrapper that only embeds the interface cannot be measured")
	assert.Equal(t, int64(0), size)

	size, ok = ReaderSize(forwardsSize{inner})
	assert.True(t, ok, "a wrapper meant to be bounded has to forward Size itself")
	assert.Equal(t, int64(2048), size)
}

type seekOnly struct{ inner *bytes.Reader }

func (s seekOnly) ReadAt(p []byte, off int64) (int, error) { return s.inner.ReadAt(p, off) }
func (s seekOnly) Seek(off int64, whence int) (int64, error) {
	return s.inner.Seek(off, whence)
}

type readAtOnly struct{ inner *bytes.Reader }

func (r readAtOnly) ReadAt(p []byte, off int64) (int, error) { return r.inner.ReadAt(p, off) }

type embedsReaderAt struct{ io.ReaderAt }

type forwardsSize struct{ io.ReaderAt }

func (f forwardsSize) Size() int64 {
	size, _ := ReaderSize(f.ReaderAt)
	return size
}

// overstatedSize answers with a size larger than the bytes behind it, the way a wrapper that returns a
// declared length rather than a measured one would.
type overstatedSize struct {
	io.ReaderAt
	size int64
}

func (o overstatedSize) Size() int64 { return o.size }

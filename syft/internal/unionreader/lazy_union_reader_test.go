package unionreader

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type spyingCloser struct {
	closed bool
	io.Reader
}

func (s *spyingCloser) Close() error {
	s.closed = true
	return nil
}

func Test_lazyUnionReader_Close(t *testing.T) {
	r := strings.NewReader("some string")
	sc := &spyingCloser{
		false,
		r,
	}
	subject := newLazyUnionReader(sc)
	require.NoError(t, subject.Close())
	assert.True(t, sc.closed)
}

func Test_lazyUnionReader_ReadAll(t *testing.T) {
	rc := io.NopCloser(strings.NewReader("some data"))
	subject := newLazyUnionReader(rc)

	b, err := io.ReadAll(subject)
	require.NoError(t, err)
	assert.Equal(t, "some data", string(b))
}

func Test_lazyUnionReader_RepeatedlyRead(t *testing.T) {
	data := "some data for our reader that we need to read!"
	rc := io.NopCloser(strings.NewReader(data))
	subject := newLazyUnionReader(rc)
	var readErr error
	var readResult []byte
	for readErr == nil {
		buf := make([]byte, 2)
		var n int
		n, readErr = subject.Read(buf)
		readResult = append(readResult, buf[:n]...)
	}
	assert.Equal(t, data, string(readResult))
	assert.ErrorIs(t, readErr, io.EOF)
}

func Test_lazyUnionReader_ReadAt(t *testing.T) {
	readStart := make([]byte, 4)
	readMid := make([]byte, 4)
	readEnd := make([]byte, 4)
	tests := []struct {
		name      string
		dst       []byte
		off       int64
		wantN     int
		wantBytes []byte
		wantEOF   bool
	}{
		{
			name:      "read first 4 bytes",
			dst:       readStart,
			off:       0,
			wantN:     4,
			wantBytes: []byte("0123"),
		},
		{
			name:      "read 4 bytes from middle",
			dst:       readMid,
			off:       4,
			wantN:     4,
			wantBytes: []byte("4567"),
		},
		{
			name:      "read last 4 bytes",
			dst:       readEnd,
			off:       12,
			wantN:     4,
			wantBytes: []byte("cdef"),
		},
		{
			name:      "read past end",
			dst:       make([]byte, 4),
			off:       14,
			wantN:     2,
			wantBytes: []byte("ef"),
			wantEOF:   true,
		},
		{
			name:    "read way out of bounds",
			dst:     make([]byte, 4),
			off:     512,
			wantN:   0,
			wantEOF: true,
		},
		{
			name:      "buffer more than available",
			dst:       make([]byte, 512),
			off:       0,
			wantN:     16,
			wantBytes: []byte("0123456789abcdef"),
			wantEOF:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := io.NopCloser(strings.NewReader("0123456789abcdef"))
			subject := newLazyUnionReader(rc)
			n, err := subject.ReadAt(tt.dst, tt.off)
			assert.Equal(t, tt.wantN, n)
			assert.Equal(t, string(tt.wantBytes), string(tt.dst[:tt.wantN]))
			if tt.wantEOF {
				assert.ErrorIs(t, err, io.EOF)
			}
		})
	}
}

func Test_lazyUnionReader_Seek(t *testing.T) {
	//const seek = 0
	//const read = 1
	type command struct {
		seekOffset int64
		seekWhence int
		readDst    []byte
	}
	data := []byte("this is a string of data that I'm very excited to share")
	tests := []struct {
		name      string
		commands  []command
		wantBytes []byte
		wantEOF   bool
	}{
		{
			name: "read the first 4 bytes twice",
			commands: []command{
				{
					readDst: make([]byte, 4),
				},
				{
					seekOffset: 0,
					seekWhence: io.SeekStart,
				},
				{
					readDst: make([]byte, 4),
				},
			},
			wantBytes: []byte("thisthis"),
		},
		{
			name: "read the last 4 bytes twice",
			commands: []command{
				{
					seekWhence: io.SeekEnd,
					seekOffset: -4,
				},
				{
					readDst: make([]byte, 4),
				},
				{
					seekWhence: io.SeekEnd,
					seekOffset: -4,
				},
				{
					readDst: make([]byte, 4),
				},
			},
			wantBytes: []byte("harehare"),
		},
		{
			name: "read 4, skip 4, read 4",
			commands: []command{
				{readDst: make([]byte, 4)},
				{seekOffset: 4, seekWhence: io.SeekCurrent},
				{readDst: make([]byte, 4)},
			},
			wantBytes: []byte("thisa st"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := io.NopCloser(bytes.NewReader(data))
			subject := newLazyUnionReader(rc)
			var readSeekErr error
			var readResult []byte
			for _, c := range tt.commands {
				var n int
				if len(c.readDst) > 0 {
					n, readSeekErr = subject.Read(c.readDst)
					readResult = append(readResult, c.readDst[:n]...)
				} else {
					_, readSeekErr = subject.Seek(c.seekOffset, c.seekWhence)
				}
			}
			if tt.wantEOF {
				assert.ErrorIs(t, readSeekErr, io.EOF)
			}
			assert.Equal(t, string(tt.wantBytes), string(readResult))
		})
	}
}

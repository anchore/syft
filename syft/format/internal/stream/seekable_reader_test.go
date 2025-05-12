package stream

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSeekableReader(t *testing.T) {
	tests := []struct {
		name    string
		input   io.Reader
		assert  func(io.Reader, io.ReadSeeker)
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "nil reader",
			input:   nil,
			wantErr: require.Error,
		},
		{
			name:  "empty reader",
			input: bytes.NewBuffer([]byte{}), // does not implement io.Seeker (but does implement io.Reader)
			assert: func(input io.Reader, got io.ReadSeeker) {
				impl, ok := got.(*bytes.Reader) // contents are copied to a byte slice, accessed via bytes.Reader
				require.True(t, ok)
				_, err := impl.Seek(0, io.SeekStart)
				require.NoError(t, err)
				content, err := io.ReadAll(impl)
				require.NoError(t, err)
				require.Equal(t, []byte{}, content)
			},
		},
		{
			name:  "empty read seeker",
			input: strings.NewReader(""), // implements io.ReadSeeker, not offset
			assert: func(input io.Reader, got io.ReadSeeker) {
				_, ok := got.(*strings.Reader) // same ReadSeeker is returned when not offset
				require.True(t, ok)
				_, err := got.Seek(0, io.SeekStart)
				require.NoError(t, err)
				content, err := io.ReadAll(got)
				require.NoError(t, err)
				require.Equal(t, []byte{}, content)
			},
		},
		{
			name:  "non-empty read seeker",
			input: strings.NewReader("hello world!"), // implements io.ReadSeeker, not offset
			assert: func(input io.Reader, got io.ReadSeeker) {
				_, ok := got.(*strings.Reader) // same ReadSeeker is returned when not offset
				require.True(t, ok)
				_, err := got.Seek(0, io.SeekStart)
				require.NoError(t, err)
				content, err := io.ReadAll(got)
				require.NoError(t, err)
				require.Equal(t, []byte("hello world!"), content)
			},
		},
		{
			name:  "non-empty reader",
			input: bytes.NewBufferString("hello world!"), // does not implement io.Seeker (but does implement io.Reader)
			assert: func(input io.Reader, got io.ReadSeeker) {
				impl, ok := got.(*bytes.Reader)
				require.True(t, ok)
				_, err := impl.Seek(0, io.SeekStart)
				require.NoError(t, err)
				content, err := io.ReadAll(impl)
				require.NoError(t, err)
				require.Equal(t, []byte("hello world!"), content)
			},
		},
		{
			name:  "position zero read seeker",
			input: strings.NewReader("a string reader"), // implements io.ReadSeeker at position 0
			assert: func(input io.Reader, got io.ReadSeeker) {
				_, ok := got.(*strings.Reader) // returns the same ReadSeeker
				require.True(t, ok)
				_, err := got.Seek(0, io.SeekStart)
				require.NoError(t, err)
				content, err := io.ReadAll(got)
				require.NoError(t, err)
				require.Equal(t, []byte("a string reader"), content)
			},
		},
		{
			name:  "offset read seeker",
			input: moveOffset(t, bytes.NewReader([]byte{1, 2, 3, 4, 5}), 3), // implements io.ReadSeeker, with an offset
			assert: func(input io.Reader, got io.ReadSeeker) {
				_, ok := got.(*offsetReadSeeker) // returns an offset-tracking ReadSeeker
				require.True(t, ok)
				_, err := got.Seek(0, io.SeekStart)
				require.NoError(t, err)
				content, err := io.ReadAll(got)
				require.NoError(t, err)
				require.Equal(t, []byte{4, 5}, content)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			got, err := SeekableReader(tt.input)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			tt.assert(tt.input, got)
		})
	}
}

func Test_offsetReadSeeker(t *testing.T) {
	abcd1234 := func() io.ReadSeeker { return strings.NewReader("abcd1234") }
	abcd1234offset := func(offset int) func() io.ReadSeeker {
		return func() io.ReadSeeker {
			r := strings.NewReader("abcd1234")
			_, err := r.Seek(int64(offset), io.SeekStart)
			require.NoError(t, err)
			return r
		}
	}

	tests := []struct {
		name     string
		input    func() io.ReadSeeker
		seek     int64
		seek2    int64
		whence   int
		expected string
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:     "basic reader",
			input:    abcd1234,
			seek:     0,
			whence:   io.SeekStart,
			expected: "abcd1234",
		},
		{
			name:     "basic reader offset",
			input:    abcd1234offset(1),
			seek:     0,
			whence:   io.SeekStart,
			expected: "bcd1234",
		},
		{
			name:     "basic reader offset both",
			input:    abcd1234offset(2),
			seek:     2,
			whence:   io.SeekStart,
			expected: "1234",
		},
		{
			name:    "basic reader offset seek current",
			input:   abcd1234offset(1),
			seek:    -1,
			whence:  io.SeekCurrent,
			wantErr: require.Error, // would be < current, which is an error
		},
		{
			name:     "valid negative offset from current",
			input:    abcd1234offset(1),
			seek:     2,
			seek2:    -1,
			whence:   io.SeekCurrent,
			expected: "cd1234",
		},
		{
			name:     "basic reader offset multiple",
			input:    abcd1234offset(2),
			seek:     3,
			seek2:    2,
			whence:   io.SeekCurrent,
			expected: "4",
		},
		{
			name:    "bad whence",
			input:   abcd1234,
			seek:    1,
			whence:  io.SeekEnd,
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rdr := tt.input()

			off, err := rdr.Seek(0, io.SeekCurrent)
			require.NoError(t, err)

			// construct new offsetReadSeeker
			sr := offsetReadSeeker{rdr: rdr, offset: off}

			_, err = sr.Seek(tt.seek, tt.whence)
			if tt.seek2 != 0 {
				require.NoError(t, err)
				_, err = sr.Seek(tt.seek2, tt.whence)
			}
			if tt.wantErr != nil {
				tt.wantErr(t, err)
				return
			} else {
				require.NoError(t, err)
			}

			buf := make([]byte, 1024)
			n, err := sr.Read(buf)
			require.NoError(t, err)
			require.Equal(t, tt.expected, string(buf[:n]))
		})
	}
}

func moveOffset(t *testing.T, reader io.ReadSeeker, offset int64) io.Reader {
	pos, err := reader.Seek(offset, io.SeekStart)
	require.NoError(t, err)
	require.Equal(t, offset, pos)
	return reader
}

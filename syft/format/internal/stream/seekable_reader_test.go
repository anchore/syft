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
				impl, ok := got.(*bytes.Reader) // implements bytes.Reader
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
			input: bytes.NewReader([]byte{}), // implements io.ReadSeeker
			assert: func(input io.Reader, got io.ReadSeeker) {
				_, ok := got.(*offsetReadSeeker)
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
			input: bytes.NewReader([]byte("hello world!")), // implements io.ReadSeeker
			assert: func(input io.Reader, got io.ReadSeeker) {
				_, ok := got.(*offsetReadSeeker)
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
		newErr   require.ErrorAssertionFunc
		seekErr  require.ErrorAssertionFunc
	}{
		{
			name:   "nil reader",
			input:  func() io.ReadSeeker { return nil },
			newErr: require.Error,
		},
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
			seekErr: require.Error, // would be < current, which is an error
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rdr := tt.input()

			sr, err := newOffsetReadSeeker(rdr)
			if tt.newErr != nil {
				tt.newErr(t, err)
				return
			} else {
				require.NoError(t, err)
			}

			_, err = sr.Seek(tt.seek, tt.whence)
			if tt.seek2 != 0 {
				require.NoError(t, err)
				_, err = sr.Seek(tt.seek2, tt.whence)
			}
			if tt.seekErr != nil {
				tt.seekErr(t, err)
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

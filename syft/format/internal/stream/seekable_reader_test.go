package stream

import (
	"bytes"
	"io"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
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
				impl, ok := got.(*bytes.Reader)
				require.True(t, ok)
				_, err := impl.Seek(0, io.SeekStart)
				require.NoError(t, err)
				content, err := io.ReadAll(impl)
				require.NoError(t, err)
				require.Equal(t, []byte{}, content)

				// assert this is the same read seeker (reflect tt.input pointer is the same as the impl pointer
				inputImpl, ok := input.(*bytes.Reader)
				require.True(t, ok)
				assert.Equal(t, reflect.ValueOf(inputImpl).Pointer(), reflect.ValueOf(impl).Pointer())
			},
		},
		{
			name:  "non-empty read seeker",
			input: bytes.NewReader([]byte("hello world!")), // implements io.ReadSeeker
			assert: func(input io.Reader, got io.ReadSeeker) {
				impl, ok := got.(*bytes.Reader)
				require.True(t, ok)
				_, err := impl.Seek(0, io.SeekStart)
				require.NoError(t, err)
				content, err := io.ReadAll(impl)
				require.NoError(t, err)
				require.Equal(t, []byte("hello world!"), content)

				// assert this is the same read seeker (reflect tt.input pointer is the same as the impl pointer
				inputImpl, ok := input.(*bytes.Reader)
				require.True(t, ok)
				assert.Equal(t, reflect.ValueOf(inputImpl).Pointer(), reflect.ValueOf(impl).Pointer())
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

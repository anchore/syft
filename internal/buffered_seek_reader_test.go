package internal

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBufferedSeeker_Read(t *testing.T) {
	tests := []struct {
		name          string
		initialData   string
		readLengths   []int
		expectedReads []string
		expectError   bool
	}{
		{
			name:          "go case (read)",
			initialData:   "Hello, World!",
			readLengths:   []int{5},
			expectedReads: []string{"Hello"},
		},
		{
			name:          "multiple reads",
			initialData:   "Hello, World!",
			readLengths:   []int{5, 8},
			expectedReads: []string{"Hello", ", World!"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := NewBufferedSeeker(io.NopCloser(bytes.NewBufferString(tt.initialData)))

			for i, length := range tt.readLengths {
				buf := make([]byte, length)
				n, err := bs.Read(buf)

				if !tt.expectError {
					assert.NoError(t, err)
					assert.Equalf(t, tt.expectedReads[i], string(buf[:n]), "read index %d", i)
				} else {
					assert.Error(t, err)
				}
			}
		})
	}
}

func TestBufferedSeeker_Seek(t *testing.T) {
	tests := []struct {
		name          string
		initialData   string
		readLengths   []int
		seekOffsets   []int64
		seekWhence    []int
		expectedReads []string
		seekError     require.ErrorAssertionFunc
		readError     require.ErrorAssertionFunc
	}{
		{
			name:          "seek start 0 without read first",
			initialData:   "Hello, World!",
			readLengths:   []int{5},
			seekOffsets:   []int64{0},
			seekWhence:    []int{io.SeekStart},
			expectedReads: []string{"Hello"},
		},
		{
			name:          "read + seek back",
			initialData:   "Hello, World!",
			readLengths:   []int{5, 8, 8},
			seekOffsets:   []int64{-1, -1, 2},
			seekWhence:    []int{io.SeekStart, io.SeekStart, io.SeekStart},
			expectedReads: []string{"Hello", ", World!", "llo, Wor"},
		},
		{
			name:          "seek past read data",
			initialData:   "Hello, World!",
			readLengths:   []int{5},
			seekOffsets:   []int64{20},
			seekWhence:    []int{io.SeekStart},
			expectedReads: []string{""},
			seekError:     require.Error,
		},
		{
			name:          "seek to end",
			initialData:   "Hello, World!",
			readLengths:   []int{-1},
			seekOffsets:   []int64{20},
			seekWhence:    []int{io.SeekEnd},
			expectedReads: []string{""},
			seekError:     require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.seekError == nil {
				tt.seekError = require.NoError
			}
			if tt.readError == nil {
				tt.readError = require.NoError
			}

			bs := NewBufferedSeeker(io.NopCloser(bytes.NewBufferString(tt.initialData)))

			for i, length := range tt.readLengths {
				if len(tt.seekOffsets) > i && tt.seekOffsets[i] >= 0 {
					_, err := bs.Seek(tt.seekOffsets[i], tt.seekWhence[i])
					tt.seekError(t, err)
					if err != nil {
						continue
					}
				}

				if length >= 0 {
					buf := make([]byte, length)
					n, err := bs.Read(buf)
					tt.readError(t, err)
					if err != nil {
						continue
					}
					assert.Equalf(t, tt.expectedReads[i], string(buf[:n]), "read index %d", i)
				}
			}
		})
	}
}

func TestBufferedSeeker_Close(t *testing.T) {
	bs := NewBufferedSeeker(io.NopCloser(bytes.NewBufferString("Hello, World!")))
	err := bs.Close()
	assert.NoError(t, err)
	n, err := bs.Read(make([]byte, 1))
	assert.Equal(t, 0, n)
	assert.Error(t, err)
}

package bundle

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fileWithSignatureAt returns a file of the given size carrying the bundle marker (8-byte header
// offset followed by the signature) starting at sigStart.
func fileWithSignatureAt(size, sigStart int, headerOffset uint64) []byte {
	data := make([]byte, size)
	binary.LittleEndian.PutUint64(data[sigStart-8:sigStart], headerOffset)
	copy(data[sigStart:], dotNetBundleSignature)
	return data
}

func TestFindSignatureOffset(t *testing.T) { //nolint:funlen
	const withMarker = 256

	tests := []struct {
		name        string
		data        []byte
		searchLimit int64
		want        int64
	}{
		{
			name:        "no signature present",
			data:        make([]byte, 512),
			searchLimit: 512,
		},
		{
			name:        "zero limit searches nothing",
			data:        fileWithSignatureAt(withMarker, 64, 0x1234),
			searchLimit: 0,
		},
		{
			// callers sum unsigned header fields into an int64, which overflows to a negative limit for
			// some header values. This must read nothing rather than sizing a buffer from it.
			name:        "negative limit reads nothing",
			data:        fileWithSignatureAt(withMarker, 64, 0x1234),
			searchLimit: math.MinInt64,
		},
		{
			name:        "limit past end of file reads only what exists",
			data:        fileWithSignatureAt(withMarker, 64, 0x1234),
			searchLimit: math.MaxInt64 / 2,
			want:        0x1234,
		},
		{
			// the bound must not shrink the window below the real file, or a legitimate marker stops being found
			name:        "limit inside the file still finds the marker",
			data:        fileWithSignatureAt(withMarker, 64, 0x1234),
			searchLimit: 128,
			want:        0x1234,
		},
		{
			name:        "limit truncates the window before the marker",
			data:        fileWithSignatureAt(withMarker, 64, 0x1234),
			searchLimit: 32,
		},
		{
			// there is no room for the 8-byte header offset before the signature
			name:        "signature too close to the start to carry an offset",
			data:        append(append([]byte{0, 0}, dotNetBundleSignature...), make([]byte, 32)...),
			searchLimit: 128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findSignatureOffset(bytes.NewReader(tt.data), tt.searchLimit)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

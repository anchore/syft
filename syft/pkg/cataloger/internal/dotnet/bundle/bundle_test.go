package bundle

import (
	"bytes"
	"encoding/binary"
	"io"
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

func TestFindSignatureOffset(t *testing.T) {
	// large enough that the marker's declared header offset lands inside the file
	const withMarker = 8192
	const headerOffset = 0x1234

	tests := []struct {
		name        string
		data        []byte
		searchLimit int64
		want        int64
		wantErr     require.ErrorAssertionFunc
	}{
		{
			name:        "no signature present",
			data:        make([]byte, withMarker),
			searchLimit: withMarker,
		},
		{
			// the limit is only a hint about how far in the marker can be. Treating a nonsensical one as
			// authoritative would let a single bogus header field hide the bundle from us.
			name:        "zero limit falls back to the whole file",
			data:        fileWithSignatureAt(withMarker, 64, headerOffset),
			searchLimit: 0,
			want:        headerOffset,
		},
		{
			// callers sum unsigned header fields into an int64, which overflows to a negative limit for
			// some header values. That must not size a buffer, and must not hide the marker either.
			name:        "negative limit falls back to the whole file",
			data:        fileWithSignatureAt(withMarker, 64, headerOffset),
			searchLimit: math.MinInt64,
			want:        headerOffset,
		},
		{
			name:        "limit past end of file reads only what exists",
			data:        fileWithSignatureAt(withMarker, 64, headerOffset),
			searchLimit: math.MaxInt64 / 2,
			want:        headerOffset,
		},
		{
			// the bound must not shrink the window below the real file, or a legitimate marker stops being found
			name:        "limit inside the file still finds the marker",
			data:        fileWithSignatureAt(withMarker, 64, headerOffset),
			searchLimit: 128,
			want:        headerOffset,
		},
		{
			name:        "limit truncates the window before the marker",
			data:        fileWithSignatureAt(withMarker, 64, headerOffset),
			searchLimit: 32,
		},
		{
			// there is no room for the 8-byte header offset before the signature
			name:        "signature too close to the start to carry an offset",
			data:        append(append([]byte{0, 0}, dotNetBundleSignature...), make([]byte, 32)...),
			searchLimit: 128,
		},
		{
			// the offset is read straight out of the file, and everything downstream seeks to it
			name:        "header offset past the end of the file is rejected",
			data:        fileWithSignatureAt(withMarker, 64, 1<<40),
			searchLimit: withMarker,
			wantErr:     require.Error,
		},
		{
			name:        "header offset of zero is rejected",
			data:        fileWithSignatureAt(withMarker, 64, 0),
			searchLimit: withMarker,
			wantErr:     require.Error,
		},
		{
			// a uint64 offset read into an int64 can land negative, which would seek backwards
			name:        "header offset that reads negative is rejected",
			data:        fileWithSignatureAt(withMarker, 64, math.MaxUint64),
			searchLimit: withMarker,
			wantErr:     require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			got, err := findSignatureOffset(bytes.NewReader(tt.data), tt.searchLimit)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

// shortReader reports a size larger than what Read will hand back, which is what unionreader does for a
// squashfs block that decompresses short. The marker may well be in the bytes we did get.
type shortReader struct {
	data []byte
	size int64
	pos  int64
}

func (r *shortReader) Read(p []byte) (int, error) {
	if r.pos >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += int64(n)
	return n, nil
}

func (r *shortReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		r.pos = offset
	case io.SeekCurrent:
		r.pos += offset
	case io.SeekEnd:
		// the lie: the file claims more than Read will produce
		r.pos = r.size + offset
	}
	return r.pos, nil
}

func TestFindSignatureOffset_ShortReadStillSearchesWhatWasRead(t *testing.T) {
	data := fileWithSignatureAt(8192, 64, 0x1234)

	// claims twice the bytes it will actually produce
	r := &shortReader{data: data, size: int64(len(data)) * 2}

	got, err := findSignatureOffset(r, int64(len(data))*2)
	require.NoError(t, err)
	assert.Equal(t, int64(0x1234), got,
		"a short read must not abort the search; the marker was in the bytes that were returned")
}

func TestRead7BitEncodedInt(t *testing.T) {
	t.Run("decodes what BinaryWriter produces", func(t *testing.T) {
		for _, tt := range []struct {
			data []byte
			want int
		}{
			{data: []byte{0x05}, want: 5},
			{data: []byte{0x80, 0x01}, want: 128},
			{data: []byte{0xFF, 0x7F}, want: 16383},
		} {
			got, err := read7BitEncodedInt(bytes.NewReader(tt.data))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		}
	})

	t.Run("too many continuation bytes is rejected", func(t *testing.T) {
		_, err := read7BitEncodedInt(bytes.NewReader([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}))
		require.Error(t, err)
	})

	// callers seek forward by whatever this returns, so a negative value would rewind them and let a
	// manifest walk re-read the same bytes for every file it claims. The shift can only carry past int32
	// where int is 32 bits, so on a 64-bit build the guard is unreachable and this pins the invariant
	// rather than the branch.
	t.Run("never returns a negative length", func(t *testing.T) {
		for _, data := range [][]byte{
			{0xFF, 0xFF, 0xFF, 0xFF, 0x0F},
			{0xFF, 0xFF, 0xFF, 0xFF, 0x7F},
			{0x80, 0x80, 0x80, 0x80, 0x08},
		} {
			got, err := read7BitEncodedInt(bytes.NewReader(data))
			if err != nil {
				continue
			}
			assert.GreaterOrEqual(t, got, 0, "a length that seeks callers backwards must be rejected")
		}
	})
}

func TestFindDepsJSONInManifest_ImpossibleEntryCountIsRejected(t *testing.T) {
	tests := []struct {
		name         string
		numFiles     int32
		majorVersion uint32
	}{
		{
			// 2^31-1 entries cannot fit in a handful of bytes, so the header is malformed rather than
			// describing a manifest worth hundreds of millions of reads
			name:     "max int32 entries in a tiny file",
			numFiles: math.MaxInt32,
		},
		{
			name:     "negative entry count",
			numFiles: -1,
		},
		{
			name:         "max int32 entries in a v6 bundle",
			numFiles:     math.MaxInt32,
			majorVersion: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(make([]byte, 512))

			_, err := findDepsJSONInManifest(r, tt.numFiles, tt.majorVersion)
			require.Error(t, err)
		})
	}
}

func TestFindDepsJSONInManifest_PlausibleEntryCountIsWalked(t *testing.T) {
	// a count the remaining bytes could hold must still be walked, or the guard would reject real bundles
	var buf bytes.Buffer
	for range 2 {
		require.NoError(t, binary.Write(&buf, binary.LittleEndian, int64(0)))   // offset
		require.NoError(t, binary.Write(&buf, binary.LittleEndian, int64(0)))   // size
		require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint8(1)))   // type: assembly
		require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint8(1)))   // path length
		require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint8('a'))) // path
	}

	got, err := findDepsJSONInManifest(bytes.NewReader(buf.Bytes()), 2, 1)
	require.NoError(t, err)
	assert.Empty(t, got, "no deps.json entry in this manifest")
}

package golang

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsUPXCompressed(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "contains UPX magic at start",
			data:     append([]byte("UPX!"), make([]byte, 100)...),
			expected: true,
		},
		{
			name:     "contains UPX magic with offset",
			data:     append(append(make([]byte, 500), []byte("UPX!")...), make([]byte, 100)...),
			expected: true,
		},
		{
			name:     "no UPX magic",
			data:     []byte("\x7FELF" + string(make([]byte, 100))),
			expected: false,
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: false,
		},
		{
			name:     "partial UPX magic",
			data:     []byte("UPX"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.data)
			result := isUPXCompressed(reader)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseUPXInfo_NotUPX(t *testing.T) {
	data := []byte("\x7FELF" + string(make([]byte, 100)))
	reader := bytes.NewReader(data)

	_, err := parseUPXInfo(reader)
	require.Error(t, err)
	assert.ErrorIs(t, err, errNotUPX)
}

func TestParseUPXInfo_ValidHeader(t *testing.T) {
	// construct a minimal valid UPX header matching actual format
	// l_info: checksum (4) + magic (4) + lsize (2) + version (1) + format (1)
	lInfo := []byte{
		0, 0, 0, 0, // l_checksum (before magic)
		'U', 'P', 'X', '!', // magic
		0, 0, // l_lsize
		14, // l_version
		22, // l_format (ELF)
	}

	// p_info (12 bytes): progid + filesize + blocksize
	pInfo := []byte{
		0, 0, 0, 0, // p_progid
		0, 0, 0x10, 0, // p_filesize = 0x100000 (1MB) little-endian
		0, 0, 0x10, 0, // p_blocksize
	}

	// b_info (12 bytes): sz_unc + sz_cpr + method + filter info
	bInfo := []byte{
		0, 0, 0x10, 0, // sz_unc = 1MB
		0, 0, 0x08, 0, // sz_cpr = 512KB (compressed)
		14, 0, 0, 0, // method=LZMA, filter info
	}

	data := append(append(lInfo, pInfo...), bInfo...)
	data = append(data, make([]byte, 100)...) // padding

	reader := bytes.NewReader(data)
	info, err := parseUPXInfo(reader)

	require.NoError(t, err)
	assert.Equal(t, uint8(14), info.version)
	assert.Equal(t, uint8(22), info.format)
	assert.Equal(t, uint32(0x100000), info.originalSize)
}

func TestDecompressUPX_UnsupportedMethod(t *testing.T) {
	// construct a header with an unsupported compression method
	lInfo := []byte{
		0, 0, 0, 0, // l_checksum
		'U', 'P', 'X', '!',
		0, 0, // l_lsize
		14, 22, // version, format
	}

	pInfo := []byte{
		0, 0, 0, 0, // p_progid
		0x00, 0x01, 0x00, 0x00, // p_filesize = 256 bytes (small for test)
		0, 0, 0x10, 0, // p_blocksize
	}

	bInfo := []byte{
		0x00, 0x01, 0x00, 0x00, // sz_unc = 256
		0x80, 0x00, 0x00, 0x00, // sz_cpr = 128
		99, 0, 0, 0, // unsupported method
	}

	data := append(append(lInfo, pInfo...), bInfo...)
	data = append(data, make([]byte, 1000)...)

	reader := bytes.NewReader(data)
	_, err := decompressUPX(reader)

	require.Error(t, err)
	assert.ErrorIs(t, err, errUnsupportedUPXMethod)
}

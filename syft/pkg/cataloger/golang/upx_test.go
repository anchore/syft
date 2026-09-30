package golang

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/imagetest"
)

// every case here is one the magic scan must reject, asserted on parseUPXInfo's errNotUPX result.
//
// Every negative case that is meant to exercise the magic scan has to carry a real ELF64 little-endian
// ident, or the container gate rejects it first and the subtest passes without the scan running at all
// (the gate and a missing magic both return errNotUPX, so nothing in the assertion can tell them apart).
// TestParseUPXInfo_OnlyELF64LittleEndian owns the gate; these own the scan.
func TestParseUPXInfo_MagicDetection(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		foundMagic bool // the magic was located (the header may still be rejected as implausible)
	}{
		{
			name:       "contains UPX magic at start",
			data:       append(append(packedELFStub(), []byte("UPX!")...), make([]byte, 100)...),
			foundMagic: true,
		},
		{
			name:       "contains UPX magic with offset",
			data:       append(append(append(packedELFStub(), make([]byte, 500)...), []byte("UPX!")...), make([]byte, 100)...),
			foundMagic: true,
		},
		{
			// UPX packs PE and Mach-O with this same l_info/p_info layout, and nothing here can place
			// their blocks, so the container has to be checked before the magic is trusted
			name: "UPX magic but not an ELF container",
			data: append([]byte("MZ\x90\x00UPX!"), make([]byte, 100)...),
		},
		{
			name: "no UPX magic",
			data: append(packedELFStub(), make([]byte, 100)...),
		},
		{
			// three of the four magic bytes must not match
			name: "partial UPX magic",
			data: append(append(packedELFStub(), []byte("UPX")...), make([]byte, 100)...),
		},
		{
			// never reaches the scan: the six byte ident read comes up short, so the container gate
			// refuses it first. Kept because an empty reader is a shape the cataloger really is handed.
			name: "empty data",
			data: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseUPXInfo(bytes.NewReader(tt.data), int64(len(tt.data)))
			require.Error(t, err, "none of these fixtures is a usable UPX header")
			if tt.foundMagic {
				assert.NotErrorIs(t, err, errNotUPX, "the magic was found, so the header was parsed and rejected")
			} else {
				assert.ErrorIs(t, err, errNotUPX)
			}
		})
	}
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

	// padded so the declared 1MB stays within maxUPXExpansion of the fixture's own size; a real UPX file
	// carries the compressed data this header describes, and the bound is measured against that.
	data := append(append(append(packedELFStub(), lInfo...), pInfo...), bInfo...)
	data = append(data, make([]byte, 0x100000/maxUPXExpansion)...)

	reader := bytes.NewReader(data)
	info, err := parseUPXInfo(reader, sizeOf(t, reader))

	require.NoError(t, err)
	assert.Equal(t, uint8(14), info.version)
	assert.Equal(t, uint8(22), info.format)
	assert.Equal(t, uint32(0x100000), info.originalSize)
}

// TestImageSmallUPXNeedsLoaderPadding checks the fixture rather than the code. UPX pads to a 4 byte
// boundary before its loader stub, and the cataloger tests over image-small-upx only catch an unpacker that
// ignores that padding if there is some. A build that needs none passes either way, which is how the bug
// went unnoticed. The case without padding is covered by TestDecompressUPX_TailExtentsArePlacedPastTheLoader.
func TestImageSmallUPXNeedsLoaderPadding(t *testing.T) {
	img := imagetest.GetFixtureImage(t, "docker-archive", "image-small-upx")
	rc, err := img.OpenPathFromSquash(stereoscopeFile.Path("/run-me"))
	require.NoError(t, err)
	data, err := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	require.NoError(t, err)

	r := bytes.NewReader(data)
	info, err := parseUPXInfo(r, int64(len(data)))
	require.NoError(t, err)
	require.NotZero(t, info.loaderSize, "real UPX output carries a loader stub")

	// walk the first run of extents to the end marker in front of the stub
	extentsEnd := info.firstBlockOff
	for blockNum := 0; ; blockNum++ {
		block, _, err := readChainBlock(r, extentsEnd, blockNum, info.inputLen)
		require.NoError(t, err)
		if block == nil {
			break
		}
		extentsEnd = block.dataOffset + int64(block.compressedSize)
	}
	require.NotZero(t, extentsEnd%4, "the fixture no longer needs padding: change the version string in its Dockerfile")
}

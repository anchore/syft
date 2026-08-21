package golang

import (
	"bytes"
	"encoding/binary"
	"io"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz/lzma"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/file"
)

// buildUPXLZMAStream encodes data into the compressed-block form decompressLZMA expects: UPX's custom
// 2-byte props header followed by the raw LZMA range-coded stream (the standard 13-byte .lzma header is
// stripped because decompressLZMA reconstructs its own). Uses the default lc=3/lp=0/pb=2 properties and a
// 64KB dictionary so the size math in decompressLZMA lines up for the small payloads used in tests.
func buildUPXLZMAStream(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := lzma.WriterConfig{
		Properties:   &lzma.Properties{LC: 3, LP: 0, PB: 2},
		DictCap:      1 << 16,
		SizeInHeader: true,
		Size:         int64(len(data)),
	}.NewWriter(&buf)
	require.NoError(t, err)
	_, err = w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	raw := buf.Bytes()[13:] // strip standard 13-byte lzma header
	// UPX 2-byte header: byte 0 is (t<<3)|pb where t = lc+lp, byte 1 is (lp<<4)|lc. Real `upx --best
	// --lzma` output for lc=3/lp=0/pb=2 is 0x1a 0x03, confirmed against the image-small-upx fixture.
	return append([]byte{0x1a, 0x03}, raw...)
}

// padTo grows data to at least size bytes so its declared p_filesize stays within maxUPXExpansion of the
// fixture's own length. Real UPX files are far larger than their headers; the crafted ones here are not,
// and the input-size bound is deliberately sensitive to that.
func padTo(data []byte, size int) []byte {
	if len(data) >= size {
		return data
	}
	return append(data, make([]byte, size-len(data))...)
}

// buildUPXHeader assembles the l_info + p_info prefix common to every crafted fixture below.
func buildUPXHeader(originalSize, blockSize uint32) []byte {
	lInfo := []byte{
		0, 0, 0, 0, // l_checksum
		'U', 'P', 'X', '!', // magic
		0, 0, // l_lsize
		14, 22, // l_version, l_format
	}
	pInfo := make([]byte, 12)
	binary.LittleEndian.PutUint32(pInfo[4:8], originalSize) // p_filesize
	binary.LittleEndian.PutUint32(pInfo[8:12], blockSize)   // p_blocksize
	return append(lInfo, pInfo...)
}

// buildUPXFile assembles a minimal but structurally valid UPX container: l_info + p_info followed by one
// b_info + compressed stream per payload, terminated by a zero end-marker block. declaredSizes, when
// non-nil, overrides each block's sz_unc so a fixture can lie about what its stream decompresses to.
func buildUPXFile(t *testing.T, originalSize, blockSize uint32, payloads [][]byte, declaredSizes []uint32) []byte {
	t.Helper()
	data := buildUPXHeader(originalSize, blockSize)
	for i, p := range payloads {
		stream := buildUPXLZMAStream(t, p)
		szUnc := uint32(len(p))
		if declaredSizes != nil {
			szUnc = declaredSizes[i]
		}
		b := make([]byte, 12)
		binary.LittleEndian.PutUint32(b[0:4], szUnc)               // sz_unc
		binary.LittleEndian.PutUint32(b[4:8], uint32(len(stream))) // sz_cpr
		b[8] = 14                                                  // b_method = LZMA
		data = append(data, b...)
		data = append(data, stream...)
	}
	return append(data, make([]byte, 12)...) // end marker: sz_unc == 0
}

// readAll drains an io.ReaderAt returned by decompressUPX.
func readAll(t *testing.T, r io.ReaderAt) []byte {
	t.Helper()
	require.NotNil(t, r)
	out, err := io.ReadAll(io.NewSectionReader(r, 0, 1<<62))
	require.NoError(t, err)
	return out
}

func TestDecompressUPX_OversizedBlockRejected(t *testing.T) {
	// a single block may not claim more output than the file's own p_filesize leaves. sz_unc used to be
	// passed straight to make(), and the reporter's proof-of-concept drove it across the uint32 range.
	cases := map[string]uint32{
		"beyond the declared original size": 8192,
		"full uint32 range":                 0xFFFFFFFF,
	}
	for name, szUnc := range cases {
		t.Run(name, func(t *testing.T) {
			data := buildUPXFile(t, 4096, 4096, [][]byte{bytes.Repeat([]byte("A"), 32)}, []uint32{szUnc})

			_, err := decompressUPX(bytes.NewReader(data))
			require.Error(t, err)
			assert.ErrorIs(t, err, errUPXOutputExceeded)
			assert.ErrorIs(t, err, errUPXDecompress, "a plausible header that fails to unpack is reportable")
		})
	}
}

func TestDecompressUPX_CumulativeExceedsOriginalSize(t *testing.T) {
	// each block individually fits within p_blocksize, but together they claim more than the file's
	// declared original size. Without the running remainder every block may claim the full size and the
	// total decompression work becomes (block count x original size). The streams are real 2048-byte
	// payloads so the failure below is the budget and not a short decode.
	payload := bytes.Repeat([]byte("A"), 2048)
	data := buildUPXFile(t, 4096, 2048, [][]byte{payload, payload, payload}, nil) // 3 x 2048 > 4096

	_, err := decompressUPX(bytes.NewReader(data))
	require.Error(t, err)
	assert.ErrorIs(t, err, errUPXOutputExceeded)
}

func TestDecompressUPX_BudgetAllowsExactlyOriginalSize(t *testing.T) {
	// the bound must not reject a file whose blocks sum to exactly the declared original size, which is
	// what a well-formed UPX binary does.
	payload := bytes.Repeat([]byte("A"), 2048)
	data := buildUPXFile(t, 4096, 2048, [][]byte{payload, payload}, nil)

	_, err := decompressUPX(bytes.NewReader(data))
	require.NoError(t, err)
}

func TestDecompressUPX_BlockCountBounded(t *testing.T) {
	// without a cap the block loop runs until the budget is spent one byte at a time, so a small file can
	// drive hundreds of millions of iterations. Each block here places a single byte sequentially, so the
	// number of blocks actually processed is directly observable in the output.
	const blocks = maxUPXBlocks + 76
	payloads := make([][]byte, blocks)
	for i := range payloads {
		payloads[i] = []byte("A")
	}
	data := buildUPXFile(t, 4096, 4096, payloads, nil)

	out, err := decompressUPX(bytes.NewReader(data))
	require.NoError(t, err, "the cap stops the loop, it does not fail the file")
	assert.Equal(t, maxUPXBlocks, bytes.Count(readAll(t, out), []byte("A")),
		"exactly maxUPXBlocks blocks should have been placed")
}

// buildELF64 assembles a minimal ELF64 header followed by the given program-header bytes.
func buildELF64(phoff uint64, phentsize, phnum uint16, phdrs []byte) []byte {
	hdr := make([]byte, 64)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F'})
	hdr[4] = 2 // ELFCLASS64
	binary.LittleEndian.PutUint64(hdr[0x20:0x28], phoff)
	binary.LittleEndian.PutUint16(hdr[0x36:0x38], phentsize)
	binary.LittleEndian.PutUint16(hdr[0x38:0x3a], phnum)
	return append(hdr, phdrs...)
}

func TestParseELFPTLoadOffsets_ShortPhentsizeNoPanic(t *testing.T) {
	// a program-header entry smaller than an ELF64 phdr would let the fixed-offset p_offset read run past
	// the entry; the parser must reject it rather than index out of range.
	phdr := []byte{1, 0, 0, 0, 0, 0, 0, 0} // ptype = PT_LOAD, only 8 bytes
	elf := buildELF64(64, 8, 1, phdr)

	require.NotPanics(t, func() {
		assert.Empty(t, parseELFPTLoadOffsets(elf))
	})
}

func TestParseELFPTLoadOffsets_OverflowPhoffNoPanic(t *testing.T) {
	// a phoff near the top of the uint64 range must not overflow the bounds check into a huge slice index.
	phdr := make([]byte, 56)
	binary.LittleEndian.PutUint32(phdr[0:4], 1) // PT_LOAD
	elf := buildELF64(0xFFFFFFFFFFFFFFF0, 56, 1, phdr)

	require.NotPanics(t, func() {
		assert.Empty(t, parseELFPTLoadOffsets(elf))
	})
}

// buildPoisonELF returns an ELF whose second PT_LOAD segment declares p_offset at the top of the uint64
// range, along with the payload set that drives block 3 to that offset.
func buildPoisonELF(t *testing.T) []byte {
	t.Helper()
	phdrs := make([]byte, 112)                                      // two ELF64 program headers
	binary.LittleEndian.PutUint32(phdrs[0:4], 1)                    // phdr[0] PT_LOAD
	binary.LittleEndian.PutUint64(phdrs[8:16], 0)                   // p_offset 0
	binary.LittleEndian.PutUint32(phdrs[56:60], 1)                  // phdr[1] PT_LOAD
	binary.LittleEndian.PutUint64(phdrs[64:72], 0xFFFFFFFFFFFFFFFF) // p_offset at the uint64 ceiling
	elf := buildELF64(64, 56, 2, phdrs)

	// sanity: the crafted offset really is parsed out, so the tests below exercise the placement guard
	require.Equal(t, []uint64{0, 0xFFFFFFFFFFFFFFFF}, parseELFPTLoadOffsets(elf))
	return elf
}

func TestDecompressUPX_OutOfRangePlacementStopsWithPartialOutput(t *testing.T) {
	// block 3 is directed at a p_offset past the end of the output buffer. The blocks placed before it are
	// often enough to recover .go.buildinfo, so they are kept, but the loop must stop rather than continue
	// from a bad offset.
	elf := buildPoisonELF(t)
	payloads := [][]byte{elf, bytes.Repeat([]byte("B"), 32), bytes.Repeat([]byte("C"), 32)}
	data := buildUPXFile(t, 8192, 8192, payloads, nil)

	out, err := decompressUPX(bytes.NewReader(data))
	require.NoError(t, err)
	got := readAll(t, out)
	assert.Equal(t, elf, got[:len(elf)], "block 1 stays placed")
	assert.NotContains(t, string(got), "CCCC", "the out-of-range block is not placed")
}

func TestDecompressUPX_OutOfRangePlacementDoesNotPoisonLaterBlocks(t *testing.T) {
	// regression: the placement guard used to skip the copy and fall through, but outputOffset is derived
	// from the rejected destOffset. With p_offset at the uint64 ceiling and a 1-byte block 3, outputOffset
	// wrapped to 0, and block 4 was then written over the reconstructed ELF header at offset 0.
	elf := buildPoisonELF(t)
	attacker := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 8)
	payloads := [][]byte{elf, bytes.Repeat([]byte("B"), 32), {0x41}, attacker}
	data := buildUPXFile(t, 8192, 8192, payloads, nil)

	out, err := decompressUPX(bytes.NewReader(data))
	require.NoError(t, err)
	got := readAll(t, out)
	assert.Equal(t, []byte{0x7f, 'E', 'L', 'F'}, got[:4], "the ELF header must not be overwritten")
	assert.NotContains(t, string(got), string(attacker), "the block after a bad offset is not placed")
}

func TestNextPowerOf2(t *testing.T) {
	cases := []struct{ in, want uint32 }{
		{0, 1},
		{1, 1},
		{3, 4},
		{1 << 20, 1 << 20},
		{(1 << 20) + 1, 1 << 21},
		{1 << 31, 1 << 31},
		{(1 << 31) + 1, 1 << 31}, // saturates rather than wrapping to 0
		{0xFFFFFFFF, 1 << 31},    // saturates rather than wrapping to 0
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, nextPowerOf2(c.in), "nextPowerOf2(%d)", c.in)
	}
}

func TestDecompressLZMA_RoundTrip(t *testing.T) {
	// happy path: a stream built with valid LZMA parameters round-trips (and confirms the parameter
	// validation does not reject legitimate values).
	data := bytes.Repeat([]byte("hello UPX "), 16)
	dst := make([]byte, len(data))
	require.NoError(t, decompressLZMA(buildUPXLZMAStream(t, data), dst))
	assert.Equal(t, data, dst)
}

func TestDecompressLZMA_InvalidParams(t *testing.T) {
	// the header nibbles can hold values the LZMA props byte cannot represent. Rejecting them keeps the
	// uint8 props arithmetic from wrapping into a valid-looking but wrong value.
	cases := map[string][]byte{
		// byte 0 low 3 bits carry pb; byte 1 is (lp<<4)|lc
		"pb above range":     {0x07, 0x03, 0x00, 0x00}, // pb = 7
		"lc above range":     {0x02, 0x0f, 0x00, 0x00}, // lc = 15
		"lp above range":     {0x02, 0x53, 0x00, 0x00}, // lp = 5
		"lc+lp above budget": {0x02, 0x48, 0x00, 0x00}, // lc = 8, lp = 4, sum = 12
	}
	for name, stream := range cases {
		t.Run(name, func(t *testing.T) {
			err := decompressLZMA(stream, make([]byte, 32))
			require.Error(t, err)
			assert.ErrorIs(t, err, errUPXInvalidLZMAParams)
		})
	}
}

func TestDecompressLZMA_LiteralBitBudgetAllowsRealValues(t *testing.T) {
	// UPX emits lc=3/lp=0, and the budget must stay clear of anything real. lc+lp at exactly the cap is
	// accepted (it fails later on the stream contents, not on the parameters).
	stream := []byte{0x02, 0x44, 0x00, 0x00} // lc = 4, lp = 4, sum = 8
	err := decompressLZMA(stream, make([]byte, 32))
	require.Error(t, err)
	assert.NotErrorIs(t, err, errUPXInvalidLZMAParams, "the cap itself must not reject lc+lp == the cap")
}

func TestUnfilter49(t *testing.T) {
	// the CTO filter stores CALL/JMP operands big-endian with cto8 as a marker byte. Reversing it must
	// restore the little-endian relative address: 0x12345678 - (pos+1) - (cto8<<24) at pos 0.
	const cto8 = 0x12
	data := []byte{0xE8, cto8, 0x34, 0x56, 0x78}
	unfilter49(data, cto8)
	assert.Equal(t, []byte{0xE8, 0x77, 0x56, 0x34, 0x00}, data)
}

func TestUnfilter49_LeavesUnmarkedBytesAlone(t *testing.T) {
	// a CALL whose next byte is not the cto8 marker was not transformed by the filter, so it must be
	// left exactly as-is.
	data := []byte{0xE8, 0x99, 0x34, 0x56, 0x78}
	want := bytes.Clone(data)
	unfilter49(data, 0x12)
	assert.Equal(t, want, data)
}

func TestParseUPXInfo_ImplausibleHeader(t *testing.T) {
	// a coincidental "UPX!" match surrounded by zeroed fields must not be accepted as a real UPX header.
	build := func(version, format byte, originalSize, blockSize uint32) []byte {
		lInfo := []byte{0, 0, 0, 0, 'U', 'P', 'X', '!', 0, 0, version, format}
		pInfo := make([]byte, 12)
		binary.LittleEndian.PutUint32(pInfo[4:8], originalSize)
		binary.LittleEndian.PutUint32(pInfo[8:12], blockSize)
		return append(append(append([]byte{}, lInfo...), pInfo...), make([]byte, 32)...)
	}

	cases := map[string][]byte{
		"zero version":               build(0, 22, 0x1000, 0x1000),
		"zero format":                build(14, 0, 0x1000, 0x1000),
		"zero block size":            build(14, 22, 0x1000, 0),
		"zero original size":         build(14, 22, 0, 0x1000),
		"original size over ceiling": build(14, 22, maxUPXOriginalSize+1, 0x1000),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseUPXInfo(bytes.NewReader(data))
			require.Error(t, err)
			assert.ErrorIs(t, err, errUPXImplausibleHeader)
		})
	}
}

func TestParseUPXInfo_BlockSizeAboveOriginalSizeAccepted(t *testing.T) {
	// p_blocksize is not a bound and must not be a rejection reason. UPX derives it from a PT_LOAD extent
	// and real output has the largest block equal to it exactly, so a check against p_filesize would run
	// with no headroom against something the format does not promise. The remainder budget bounds output.
	data := padTo(append(buildUPXHeader(0x1000, 0x2000), make([]byte, 32)...), 128)

	info, err := parseUPXInfo(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, uint32(0x2000), info.blockSize)
}

func TestParseUPXInfo_HighExpansionAccepted(t *testing.T) {
	// LZMA encodes a run of N identical bytes in O(log N), so a `go:embed` of 120MB of zeros packs
	// 127504546 bytes into 608940 and `upx --best --lzma` produces exactly that. maxUPXExpansion must be
	// loose enough for it: the ratio here is 209x against a 610KB input, well inside the 1024x allowance.
	data := padTo(buildUPXHeader(127504546, 126628216), 610*1024)

	info, err := parseUPXInfo(bytes.NewReader(data))
	require.NoError(t, err, "a high but legitimate expansion ratio must not be rejected")
	assert.Equal(t, uint32(127504546), info.originalSize)
}

func TestParseUPXInfo_CeilingAcceptedWhenTheInputPaysForIt(t *testing.T) {
	// the absolute ceiling is legal, but only for a file large enough to claim it
	data := padTo(buildUPXHeader(maxUPXOriginalSize, maxUPXOriginalSize), maxUPXOriginalSize/maxUPXExpansion)

	info, err := parseUPXInfo(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, uint32(maxUPXOriginalSize), info.originalSize)
}

func TestParseUPXInfo_TinyInputCannotClaimALargeOriginalSize(t *testing.T) {
	// regression: p_filesize sizes the output buffer directly, so without a bound against the actual input
	// a header of a few dozen bytes could claim the absolute ceiling. A 128 byte file may claim 128KB.
	data := padTo(buildUPXHeader(maxUPXOriginalSize, 4096), 128)

	_, err := parseUPXInfo(bytes.NewReader(data))
	require.Error(t, err)
	assert.ErrorIs(t, err, errUPXImplausibleHeader)

	withinAllowance := padTo(buildUPXHeader(128*maxUPXExpansion, 4096), 128)
	_, err = parseUPXInfo(bytes.NewReader(withinAllowance))
	assert.NoError(t, err, "exactly the allowance is legal; only past it is not")
}

// seekOnlyReader has ReadAt and Seek but no Size(), which is the shape the readers in a real scan have:
// GetReaders hands back the *os.File itself for a non-macho binary.
type seekOnlyReader struct{ r *bytes.Reader }

func (s *seekOnlyReader) ReadAt(p []byte, off int64) (int, error) { return s.r.ReadAt(p, off) }
func (s *seekOnlyReader) Seek(off int64, whence int) (int64, error) {
	return s.r.Seek(off, whence)
}

func TestInputSize(t *testing.T) {
	// the whole input-size bound goes inert if this returns 0, and the reader that reaches it in a real
	// scan is an *os.File, which answers Seek but not Size(). Both paths have to work.
	data := make([]byte, 4096)

	assert.Equal(t, int64(4096), inputSize(bytes.NewReader(data)), "*bytes.Reader answers Size() directly")
	assert.Equal(t, int64(4096), inputSize(&seekOnlyReader{bytes.NewReader(data)}), "Seek-only must fall back, not give up")

	t.Run("seeking restores the original offset", func(t *testing.T) {
		r := &seekOnlyReader{bytes.NewReader(data)}
		_, err := r.Seek(100, io.SeekStart)
		require.NoError(t, err)
		require.Equal(t, int64(4096), inputSize(r))
		at, err := r.Seek(0, io.SeekCurrent)
		require.NoError(t, err)
		assert.Equal(t, int64(100), at, "measuring the size must not move the caller's cursor")
	})

	t.Run("unknown size falls back to the absolute ceiling", func(t *testing.T) {
		// io.ReaderAt with neither Size() nor Seek: the ratio cannot be applied, so only the cap remains
		plain := struct{ io.ReaderAt }{bytes.NewReader(data)}
		assert.Zero(t, inputSize(plain))
		assert.Equal(t, uint64(maxUPXOriginalSize), maxOriginalSize(plain))
	})
}

func TestDecompressUPX_AllocationTracksTheInput(t *testing.T) {
	// the property every bound in this file exists to protect, asserted directly rather than through an
	// error value: a small file cannot drive a large allocation. Pre-fix a ~100 byte input reached
	// make([]byte, 0xFFFFFFFF); an intermediate version capped that at the absolute 500MB ceiling, which
	// a 100 byte file could still claim in full.
	tiny := padTo(buildUPXHeader(maxUPXOriginalSize, maxUPXOriginalSize), 128)

	allocated := measureAlloc(t, func() {
		_, err := decompressUPX(bytes.NewReader(tiny))
		require.Error(t, err)
	})
	assert.Less(t, allocated, uint64(1<<20), "a 128 byte input must not drive a megabyte of allocation")
	t.Logf("128 byte input allocated %d bytes", allocated)
}

func TestDecompressUPX_HeaderWithoutDecodableBlocksAllocatesNothing(t *testing.T) {
	// a header declaring a large p_filesize whose first b_info is the end marker used to allocate the whole
	// output buffer and return success. output is now allocated on the first block that survives
	// validation, so this costs nothing and reports that the file is not really packed.
	data := padTo(append(buildUPXHeader(4*intFile.MB, 4096), make([]byte, 12)...), 8*1024)

	allocated := measureAlloc(t, func() {
		_, err := decompressUPX(bytes.NewReader(data))
		require.Error(t, err)
		assert.ErrorIs(t, err, errUPXImplausibleHeader)
		assert.NotErrorIs(t, err, errUPXDecompress, "nothing was packed, so there is nothing to report")
	})
	assert.Less(t, allocated, uint64(256<<10), "no block survived validation, so no output buffer is due")
}

func TestDecompressUPX_UnsupportedMethodIsNotReportable(t *testing.T) {
	// upx defaults to NRV2B unless --lzma is passed, and only LZMA is implemented here. A packed non-Go
	// binary must not turn into an SBOM unknown from the golang cataloger, so the unsupported-method error
	// must stay clear of errUPXDecompress.
	block := make([]byte, 12)
	binary.LittleEndian.PutUint32(block[0:4], 256) // sz_unc
	binary.LittleEndian.PutUint32(block[4:8], 32)  // sz_cpr
	block[8] = 2                                   // b_method = NRV2B
	data := padTo(append(buildUPXHeader(4096, 4096), block...), 128)

	_, err := decompressUPX(bytes.NewReader(data))
	require.Error(t, err)
	assert.ErrorIs(t, err, errUnsupportedUPXMethod)
	assert.NotErrorIs(t, err, errUPXDecompress, "an unimplemented method is a capability gap, not a gap in the SBOM")
}

// TestGetBuildInfo_MaliciousUPXRejected exercises the entry point the reported vulnerability was reachable
// through. The unit tests above call decompressUPX directly; this one goes through getBuildInfo, which is
// what parseGoBinary uses and what the default-enabled go-module-binary-cataloger reaches.
func TestGetBuildInfo_MaliciousUPXRejected(t *testing.T) {
	// a plausible ELF prefix so the file looks like an executable, then a UPX header whose single block
	// claims the full uint32 range. Pre-fix this reached make([]byte, 0xFFFFFFFF).
	elf := make([]byte, 64)
	copy(elf, []byte{0x7f, 'E', 'L', 'F'})
	elf[4] = 2

	data := append(elf, buildUPXFile(t, 4096, 4096,
		[][]byte{bytes.Repeat([]byte("A"), 32)}, []uint32{0xFFFFFFFF})...)

	// go's own test timeout covers "did not return promptly"; a goroutine plus time.After here would
	// assert on an already-finished test if it ever fired.
	var bi *debug.BuildInfo
	var err error
	allocated := measureAlloc(t, func() {
		bi, err = getBuildInfo(bytes.NewReader(data), file.NewLocation("/malicious"))
	})
	assert.Nil(t, bi)
	assert.Error(t, err)
	assert.ErrorIs(t, err, errUPXDecompress, "a packed binary we cannot unpack is worth reporting")
	assert.Less(t, allocated, uint64(1<<20), "the rejection must not cost a megabyte")
}

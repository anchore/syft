package golang

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz/lzma"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/spillbuf"
	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/internal/unknown"
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

// packedELFStub is the ELF header a real UPX-packed file starts with: UPX writes its own loader as an ELF
// and puts l_info behind it. parseUPXInfo requires it, since the block placement it drives reads PT_LOAD
// offsets out of ELF program headers and would be reading nonsense from any other container.
func packedELFStub() []byte {
	stub := make([]byte, 64)
	copy(stub, []byte{0x7f, 'E', 'L', 'F'})
	stub[4] = 2 // ELFCLASS64
	stub[5] = 1 // little endian
	stub[6] = 1 // EV_CURRENT
	return stub
}

// buildUPXHeader assembles the l_info + p_info prefix common to every crafted fixture below, with no
// loader stub. Use buildUPXHeaderWithLoader to exercise the chain past the loader.
func buildUPXHeader(originalSize, blockSize uint32) []byte {
	return buildUPXHeaderWithLoader(originalSize, blockSize, 0)
}

// buildUPXHeaderWithLoader is buildUPXHeader with a non-zero l_lsize, which is what makes the block chain
// pick back up past the loader stub and place the tail extents through firstHole.
func buildUPXHeaderWithLoader(originalSize, blockSize uint32, loaderSize uint16) []byte {
	lInfo := []byte{ //nolint:gocritic // appended to the stub below
		0, 0, 0, 0, // l_checksum
		'U', 'P', 'X', '!', // magic
		byte(loaderSize), byte(loaderSize >> 8), // l_lsize
		14, 22, // l_version, l_format
	}
	pInfo := make([]byte, 12)
	binary.LittleEndian.PutUint32(pInfo[4:8], originalSize) // p_filesize
	binary.LittleEndian.PutUint32(pInfo[8:12], blockSize)   // p_blocksize
	return append(append(packedELFStub(), lInfo...), pInfo...)
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

// blockFor builds one b_info + compressed stream for the given payload.
func blockFor(t *testing.T, payload []byte) []byte {
	t.Helper()
	return filteredBlockFor(t, payload, 0, 0)
}

// filteredBlockFor is blockFor with b_ftid and b_cto8 set. Real `upx --best --lzma` on x86-64 always emits
// the CTO filter, so without this the whole unfilter path is only reachable from the Docker fixture.
func filteredBlockFor(t *testing.T, payload []byte, filterID, cto8 byte) []byte {
	t.Helper()
	stream := buildUPXLZMAStream(t, payload)
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:4], uint32(len(payload)))
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(stream)))
	b[8] = 14 // b_method = LZMA
	b[9] = filterID
	b[10] = cto8
	return append(b, stream...)
}

// unpack runs decompressUPX against a throwaway temp directory.
func unpack(t *testing.T, data []byte) (*spillbuf.Buffer, error) {
	t.Helper()
	return unpackIn(t, t.TempDir(), data)
}

// unpackIn is unpack with a caller-chosen temp directory, so a test can look at the file that was left in
// it. Parses the header the same way unpackUPX does so a fixture that is not UPX at all still reports it.
func unpackIn(t *testing.T, dir string, data []byte) (*spillbuf.Buffer, error) {
	t.Helper()
	r := bytes.NewReader(data)
	info, err := parseUPXInfo(r, sizeOf(t, r))
	if err != nil {
		return nil, err
	}
	out, err := decompressUPX(context.Background(), tmpdir.FromPath(dir), r, info)
	if out != nil {
		t.Cleanup(func() { _ = out.Close() })
	}
	return out, err
}

// readAll drains the reconstruction returned by decompressUPX. Size is the contiguous run rebuilt, so
// this is exactly what the buffer is willing to stand behind.
func readAll(t *testing.T, b *spillbuf.Buffer) []byte {
	t.Helper()
	require.NotNil(t, b)
	out := make([]byte, b.Size())
	if len(out) == 0 {
		return nil
	}
	n, err := b.ReadAt(out, 0)
	require.NoError(t, err)
	require.Equal(t, len(out), n)
	return out
}

func TestDecompressUPX_OversizedBlockRejected(t *testing.T) {
	// a single block may not claim more output than the file's own p_filesize leaves, across the full
	// uint32 range sz_unc can carry.
	cases := []struct {
		name  string
		szUnc uint32
	}{
		{"beyond the declared original size", 8192},
		{"full uint32 range", 0xFFFFFFFF},
	}
	for _, tt := range cases {
		szUnc := tt.szUnc
		t.Run(tt.name, func(t *testing.T) {
			data := buildUPXFile(t, 4096, 4096, [][]byte{bytes.Repeat([]byte("A"), 32)}, []uint32{szUnc})

			_, err := unpack(t, data)
			require.Error(t, err)
			assert.ErrorIs(t, err, errUPXOutputExceeded)
			assert.ErrorIs(t, err, errUPXDecompress, "a plausible header that fails to unpack is reportable")
		})
	}
}

// TestReadChainBlock_ZeroCompressedSizeOnTheFirstBlockIsQuiet is where the sz_cpr == 0 guard is load
// bearing. On the first block there is nothing placed yet, so without the guard the empty buffer reaches
// the decoder, fails, and a b_info the format cannot mean becomes a reported errUPXDecompress unknown
// instead of a file we quietly decline.
func TestReadChainBlock_ZeroCompressedSizeOnTheFirstBlockIsQuiet(t *testing.T) {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:4], 1) // sz_unc = 1, sz_cpr = 0
	b[8] = 14                                // b_method = LZMA

	_, err := unpack(t, padTo(append(buildUPXHeader(4096, 4096), b...), 256))
	require.ErrorIs(t, err, errUPXImplausibleHeader, "nothing in the chain was decodable")
	assert.NotErrorIs(t, err, errUPXDecompress,
		"a b_info the format cannot mean is not a packed binary we failed to read")
}

func TestReadChainBlock_LargeCompressedSizeIsNotTruncated(t *testing.T) {
	// sz_cpr is taken whole and bounded against the input rather than masked to its low 24 bits: a block
	// declaring more than 16MB of compressed data must end the chain, not decode a truncated count of a
	// longer stream.
	stream := buildUPXLZMAStream(t, bytes.Repeat([]byte("A"), 2048))
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:4], 2048)
	// masks to len(stream), so the old code read exactly the bytes that are there and decoded them
	binary.LittleEndian.PutUint32(b[4:8], 0x01000000|uint32(len(stream)))
	b[8] = 14 // b_method = LZMA

	data := append(buildUPXHeader(4096, 2048), b...)
	data = append(data, stream...)

	_, err := unpack(t, data)
	require.ErrorIs(t, err, errUPXImplausibleHeader, "no block is decodable, so this is not a packed binary")
}

func TestDecompressUPX_CumulativeExceedsOriginalSize(t *testing.T) {
	// each block individually fits within p_blocksize, but together they claim more than the file's
	// declared original size. Without the running remainder every block may claim the full size and the
	// total decompression work becomes (block count x original size). The streams are real 2048-byte
	// payloads so what stops the run below is the budget and not a short decode.
	//
	// The budget is a bound, not a verdict: the blocks that fit are kept and the chain ends at the one that
	// does not, since past the first block an overrun is indistinguishable from the loader bytes behind the
	// last real block. TestDecompressUPX_OversizedBlockRejected covers the first-block case, which does
	// fail the file.
	//
	// It is also not a gap. The file declared 4096 bytes and got 4096 bytes back, so nothing downstream is
	// short and there is nothing to report: the blocks past the budget were claims about bytes the file
	// never said it had. TestScanReader_PartialReconstructionIsReported covers a chain that really did
	// come up short of its own p_filesize.
	payload := bytes.Repeat([]byte("A"), 2048)
	blocks := make([][]byte, 10)
	for i := range blocks {
		blocks[i] = payload
	}
	data := buildUPXFile(t, 4096, 2048, blocks, nil) // 10 x 2048 against a 4096 byte p_filesize

	out, err := unpack(t, data)
	require.NoError(t, err, "the declared original size was rebuilt in full, so there is no gap to report")
	assert.Len(t, readAll(t, out), 4096, "the reconstruction may not exceed the declared original size")
}

func TestDecompressUPX_BudgetAllowsExactlyOriginalSize(t *testing.T) {
	// the bound must not reject a file whose blocks sum to exactly the declared original size, which is
	// what a well-formed UPX binary does.
	payload := bytes.Repeat([]byte("A"), 2048)
	data := buildUPXFile(t, 4096, 2048, [][]byte{payload, payload}, nil)

	_, err := unpack(t, data)
	require.NoError(t, err)
}

func TestDecompressUPX_BlockCountBounded(t *testing.T) {
	// without a cap the block loop runs until the budget is spent one byte at a time, so a small file can
	// drive hundreds of millions of iterations. Each block here places a single byte sequentially, so the
	// number of blocks actually processed is directly observable in the output.
	const blocks = maxUPXBlocks + 76
	// one stream, reused: buildUPXLZMAStream spins up a writer with a 64KB dictionary per call, so
	// building this fixture block by block cost more than the decode it is testing
	one := blockFor(t, []byte("A"))
	data := buildUPXHeader(4096, 4096)
	for range blocks {
		data = append(data, one...)
	}
	data = append(data, make([]byte, 12)...) // end marker

	out, err := unpack(t, data)
	require.ErrorIs(t, err, errUPXPartial, "the cap stops the loop and reports the rest as a gap")
	require.NotNil(t, out, "the cap does not fail the file")
	assert.Equal(t, maxUPXBlocks, bytes.Count(readAll(t, out), []byte("A")),
		"exactly maxUPXBlocks blocks should have been placed")
}

// buildELF64 assembles a minimal ELF64 header followed by the given program-header bytes.
func buildELF64(phoff uint64, phentsize, phnum uint16, phdrs []byte) []byte {
	hdr := make([]byte, 64)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F'})
	hdr[4] = 2 // ELFCLASS64
	hdr[5] = 1 // little endian
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
	//
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
	// block 3 is directed at a p_offset past the end of the declared file. The blocks placed before it are
	// often enough to recover .go.buildinfo, so they are kept, but the loop must stop rather than continue
	// from a bad offset.
	elf := buildPoisonELF(t)
	payloads := [][]byte{elf, bytes.Repeat([]byte("B"), 32), bytes.Repeat([]byte("C"), 32)}
	data := buildUPXFile(t, 8192, 8192, payloads, nil)

	out, err := unpack(t, data)
	require.ErrorIs(t, err, errUPXPartial, "the blocks given up are reported, not dropped silently")
	got := readAll(t, out)
	assert.Equal(t, elf, got[:len(elf)], "block 1 stays placed")
	assert.NotContains(t, string(got), "CCCC", "the out-of-range block is not placed")
}

func TestDecompressUPX_OutOfRangePlacementDoesNotPoisonLaterBlocks(t *testing.T) {
	// outputOffset is derived from destOffset even when destOffset is rejected, so a p_offset at the
	// uint64 ceiling can wrap outputOffset to 0: with a 1-byte block 3, block 4 must not then land over the
	// reconstructed ELF header at offset 0.
	elf := buildPoisonELF(t)
	attacker := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 8)
	payloads := [][]byte{elf, bytes.Repeat([]byte("B"), 32), {0x41}, attacker}
	data := buildUPXFile(t, 8192, 8192, payloads, nil)

	out, err := unpack(t, data)
	require.ErrorIs(t, err, errUPXPartial)
	got := readAll(t, out)
	assert.Equal(t, []byte{0x7f, 'E', 'L', 'F'}, got[:4], "the ELF header must not be overwritten")
	assert.NotContains(t, string(got), string(attacker), "the block after a bad offset is not placed")
}

func TestDecompressLZMA_RoundTrip(t *testing.T) {
	// happy path: a stream built with valid LZMA parameters round-trips (and confirms the parameter
	// validation does not reject legitimate values).
	data := bytes.Repeat([]byte("hello UPX "), 16)
	src, err := decompressLZMA(buildUPXLZMAStream(t, data), int64(len(data)))
	require.NoError(t, err)
	got, err := io.ReadAll(src)
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

func TestDecompressLZMA_InvalidParams(t *testing.T) {
	// the header nibbles can hold values the LZMA props byte cannot represent. Rejecting them keeps the
	// uint8 props arithmetic from wrapping into a valid-looking but wrong value.
	// byte 0 low 3 bits carry pb; byte 1 is (lp<<4)|lc
	cases := []struct {
		name   string
		stream []byte
	}{
		{"pb above range", []byte{0x07, 0x03, 0x00, 0x00}},     // pb = 7
		{"lc above range", []byte{0x02, 0x0f, 0x00, 0x00}},     // lc = 15
		{"lp above range", []byte{0x02, 0x53, 0x00, 0x00}},     // lp = 5
		{"lc+lp above budget", []byte{0x02, 0x48, 0x00, 0x00}}, // lc = 8, lp = 4, sum = 12
	}
	for _, tt := range cases {
		stream := tt.stream
		t.Run(tt.name, func(t *testing.T) {
			_, err := decompressLZMA(stream, 32)
			require.Error(t, err)
			assert.ErrorIs(t, err, errUPXInvalidLZMAParams)
		})
	}
}

func TestDecompressLZMA_LiteralBitBudgetAllowsRealValues(t *testing.T) {
	// UPX emits lc=3/lp=0, and the budget must stay clear of anything real. lc+lp at exactly the cap is
	// accepted (it fails later on the stream contents, not on the parameters).
	stream := []byte{0x02, 0x44, 0x00, 0x00} // lc = 4, lp = 4, sum = 8
	_, err := decompressLZMA(stream, 32)
	require.Error(t, err)
	assert.NotErrorIs(t, err, errUPXInvalidLZMAParams, "the cap itself must not reject lc+lp == the cap")
}

func TestUnfilter49(t *testing.T) {
	// the CTO filter stores CALL/JMP operands big-endian with cto8 as a marker byte. Reversing it must
	// restore the little-endian relative address: 0x12345678 - (pos+1) - (cto8<<24) at pos 0.
	const cto8 = 0x12
	data := []byte{0xE8, cto8, 0x34, 0x56, 0x78}
	unfilter49(data, cto8, 0, true)
	assert.Equal(t, []byte{0xE8, 0x77, 0x56, 0x34, 0x00}, data)
}

func TestUnfilter49_LeavesUnmarkedBytesAlone(t *testing.T) {
	// a CALL whose next byte is not the cto8 marker was not transformed by the filter, so it must be
	// left exactly as-is.
	data := []byte{0xE8, 0x99, 0x34, 0x56, 0x78}
	want := bytes.Clone(data)
	unfilter49(data, 0x12, 0, true)
	assert.Equal(t, want, data)
}

func TestCopyUnfiltered_MatchesTheWholeBlockFilter(t *testing.T) {
	// the unfilter runs over a window rather than the whole block, so the windowing is only correct if it
	// lands on exactly the bytes the in-place pass over the whole block would have. The seam between two
	// windows is at a fixed offset, so the pattern is rotated instead: every phase puts a different
	// instruction across the seam, and the conditional-jump form (which needs a sixth byte the CALL form
	// does not) is the one a carry a single byte too small drops on the floor.
	const cto8 = 0x24
	pattern := []byte{0xE8, cto8, 0x11, 0x22, 0x33, 0x0F, 0x85, cto8, 0x44, 0x55, 0x66, 0xE9, cto8}

	// every phase runs at the small sizes; the window-crossing sizes are an order of magnitude more
	// expensive per subtest, and the seam sits at a fixed offset, so two phases suffice to cross it
	small := []int{64, upxFilterWindow}
	crossing := []int{upxFilterWindow - 1, upxFilterWindow + 64, 2*upxFilterWindow + 777}
	for phase := range len(pattern) {
		rotated := append(bytes.Clone(pattern[phase:]), pattern[:phase]...)
		sizes := small
		if phase < 2 {
			sizes = append(slices.Clone(small), crossing...)
		}
		for _, size := range sizes {
			t.Run(fmt.Sprintf("phase %d, %d byte block", phase, size), func(t *testing.T) {
				block := bytes.Repeat(rotated, size/len(rotated)+1)[:size]

				want := bytes.Clone(block)
				unfilter49(want, cto8, 0, true)
				require.NotEqual(t, block, want, "the fixture must actually be filtered")

				var got bytes.Buffer
				require.NoError(t, copyUnfiltered(&got, bytes.NewReader(block), int64(size), cto8))

				require.Equal(t, size, got.Len())
				assert.True(t, bytes.Equal(want, got.Bytes()), "windowed output differs from the whole-block filter")
			})
		}
	}
}

// TestCopyUnfiltered_BlocksTooSmallToFilter covers the sizes below the filter's lookahead, where
// unfilter49's limit clamps to zero and the first window is already the final one. Nothing is
// transformable, so the bytes must come through untouched rather than panicking or being dropped.
func TestCopyUnfiltered_BlocksTooSmallToFilter(t *testing.T) {
	const cto8 = 0x24
	for size := 0; size < 7; size++ {
		t.Run(fmt.Sprintf("%d byte block", size), func(t *testing.T) {
			block := bytes.Repeat([]byte{0xE8, cto8, 0x11, 0x22, 0x33, 0x0F}, 2)[:size]
			want := bytes.Clone(block)
			unfilter49(want, cto8, 0, true)

			var got bytes.Buffer
			require.NoError(t, copyUnfiltered(&got, bytes.NewReader(block), int64(size), cto8))
			require.Equal(t, size, got.Len())
			assert.True(t, bytes.Equal(want, got.Bytes()), "windowed output differs from the whole-block filter")
		})
	}
}

// firstHole moved to spillbuf.FirstGap: placing output is the buffer's question to answer, and its
// tests live with it in internal/spillbuf.

func TestParseUPXInfo_ImplausibleHeader(t *testing.T) {
	// a coincidental "UPX!" match surrounded by zeroed fields must not be accepted as a real UPX header.
	build := func(version, format byte, originalSize, blockSize uint32) []byte {
		lInfo := []byte{0, 0, 0, 0, 'U', 'P', 'X', '!', 0, 0, version, format}
		pInfo := make([]byte, 12)
		binary.LittleEndian.PutUint32(pInfo[4:8], originalSize)
		binary.LittleEndian.PutUint32(pInfo[8:12], blockSize)
		return append(append(append(packedELFStub(), lInfo...), pInfo...), make([]byte, 32)...)
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"zero version", build(0, 22, 0x1000, 0x1000)},
		{"zero format", build(14, 0, 0x1000, 0x1000)},
		{"zero block size", build(14, 22, 0x1000, 0)},
		{"zero original size", build(14, 22, 0, 0x1000)},
	}
	for _, tt := range cases {
		data := tt.data
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(data)
			_, err := parseUPXInfo(r, sizeOf(t, r))
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

	info, err := parseUPXInfo(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	assert.Equal(t, uint32(0x2000), info.blockSize)
}

// TestParseUPXInfo_SizeClaims pins both bounds on p_filesize in both directions: the ratio against the
// input's own length, and the absolute ceiling the ratio cannot supply on its own because padding an input
// is nearly free to an attacker (a gzipped layer stores 16MB of zeros in about 16KB).
func TestParseUPXInfo_SizeClaims(t *testing.T) {
	tests := []struct {
		name     string
		original uint32
		inputLen int
		accept   bool
	}{
		{
			// LZMA encodes a run of N identical bytes in O(log N), so a `go:embed` of 120MB of zeros packs
			// 127504546 bytes into 608940 and `upx --best --lzma` produces exactly that: 209x against a
			// 610KB input, inside the 256x allowance. This is the largest legitimate original measured, and
			// what both bounds have to stay clear of.
			name: "a high but legitimate expansion ratio", original: 127504546, inputLen: 610 * 1024, accept: true,
		},
		{
			name: "a large legitimate original", original: maxUPXOriginalSize - intFile.MB,
			inputLen: (maxUPXOriginalSize-intFile.MB)/maxUPXExpansion + 1024, accept: true,
		},
		{name: "exactly the ratio allowance", original: 128 * maxUPXExpansion, inputLen: 128, accept: true},
		{name: "past the ratio allowance", original: 128*maxUPXExpansion + 1, inputLen: 128},
		{
			// deliberately pays the ratio: a 16MB input can justify 4GB at 256x, so only the ceiling stops it
			name: "past the ceiling even when the ratio allows it", original: maxUPXOriginalSize + 1,
			inputLen: 16 * intFile.MB,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := padTo(buildUPXHeader(tt.original, 0x1000), tt.inputLen)

			info, err := parseUPXInfo(bytes.NewReader(data), int64(len(data)))
			if tt.accept {
				require.NoError(t, err, "a legitimate claim must not be dropped")
				assert.Equal(t, tt.original, info.originalSize)
				return
			}
			require.Error(t, err)
			// reported, not quiet: this is a file that really is packed and that we declined to expand,
			// which is a gap we chose to leave rather than a stray "UPX!" in a string constant
			assert.ErrorIs(t, err, errUPXSizeRefused)
			assert.NotErrorIs(t, err, errUPXImplausibleHeader)
			assert.NotErrorIs(t, err, errUPXDecompress)
		})
	}
}

func TestParseUPXInfo_UnsizedInputRefused(t *testing.T) {
	// every bound is a ratio against the input, so an input that cannot be sized has nothing to weigh a
	// claim against. Quiet, like every other "not something we can read" refusal.
	data := padTo(buildUPXHeader(0x1000, 0x1000), 4096)
	plain := struct{ io.ReaderAt }{bytes.NewReader(data)}

	size, ok := intFile.ReaderSize(plain)
	require.False(t, ok, "a wrapper that only embeds the interface cannot be sized")

	_, err := parseUPXInfo(plain, size)
	require.Error(t, err)
	assert.ErrorIs(t, err, errUPXImplausibleHeader)

	// and the caller declines to unpack rather than running the bounds against a zero
	contents, err := unpackUPX(context.Background(), plain)
	require.NoError(t, err)
	t.Cleanup(func() { _ = contents.Close() })
	assert.Nil(t, contents)
}

func TestDecompressUPX_RefusingATinyClaimIsCheap(t *testing.T) {
	// the refusal half of the property every bound in this file exists to protect: a small file claiming
	// a lot is turned away before anything is sized by the claim. Pre-fix a ~100 byte input reached
	// make([]byte, 0xFFFFFFFF).
	//
	// The fixture carries a real decodable block on purpose: a header alone would exercise none of the
	// reconstruction, since nothing downstream of parseUPXInfo would ever run.
	tiny := padTo(buildUPXFile(t, 1<<30, 1<<30,
		[][]byte{bytes.Repeat([]byte("A"), 32)}, nil), 128)

	allocated := measureAlloc(t, func() {
		_, err := unpackIn(t, t.TempDir(), tiny)
		require.Error(t, err, "a 128 byte file may not claim a gigabyte")
	})
	// a tripwire on the refusal staying in front of the work, not a bound with teeth of its own: the
	// refusal happens in parseUPXInfo, so the only allocation on this path is the 8KB scan window. The
	// require.Error above is what fails if the ratio and the ceiling are both removed.
	assert.Less(t, allocated, uint64(1<<20), "a refused header must not reach anything sized by the claim")
	t.Logf("128 byte input allocated %d bytes", allocated)
}

func TestDecompressUPX_OutputIsNeverResident(t *testing.T) {
	// the reason the reconstruction goes through spillbuf rather than a []byte: a fixture that is fully
	// accepted and fully decoded must not cost its own output in heap.
	//
	// 16MB of zeros through a 64KB input. Nothing here is refused: p_filesize sits exactly at the ratio
	// the input pays for, and the whole 16MB really is written.
	const payload = 16 * intFile.MB
	const inputLen = payload / maxUPXExpansion

	block := make([]byte, payload)
	stream := buildUPXLZMAStream(t, block) // the same bytes buildUPXFile below will encode, to size the dictionary

	fixture := padTo(buildUPXFile(t, payload, payload, [][]byte{block}, nil), inputLen)
	require.LessOrEqual(t, len(fixture), inputLen, "the fixture must stay small enough for the ratio to bind")

	var out *spillbuf.Buffer
	allocated := measureAlloc(t, func() {
		var err error
		out, err = unpackIn(t, t.TempDir(), fixture)
		require.NoError(t, err)
	})

	require.Equal(t, int64(payload), out.Size(), "the whole payload must actually have been rebuilt")

	// a fixed budget, not one that scales with the output (a formula like payload/4 would still pass an
	// implementation that kept a quarter of it resident): spillbuf's memory tier, bounded a few times over
	// DefaultMemLimit for the geometric growth that holds the old copy while it doubles, plus the LZMA
	// dictionary this block's actual compressed length implies. Neither term grows with payload.
	budget := uint64(4*spillbuf.DefaultMemLimit) + uint64(maxDictionaryFor(len(stream)))
	assert.Less(t, allocated, budget,
		"decompressing %d bytes must cost the tier and the dictionary, not a fraction of the output", payload)
	t.Logf("%d byte output cost %d bytes of allocation from a %d byte input (budget %d, dictionary %d)",
		payload, allocated, len(fixture), budget, maxDictionaryFor(len(stream)))
}

func TestMaxDictionaryFor(t *testing.T) {
	// the dictionary is the last allocation still sized by something a block declares about itself, so it
	// is bounded by the compressed bytes that block actually brought with it.
	assert.Equal(t, uint32(minUPXDictionary), maxDictionaryFor(0), "a block with nothing in it gets the floor")
	assert.Equal(t, uint32(minUPXDictionary), maxDictionaryFor(64), "a tiny block cannot reach past the floor")
	// strictly between the floor and the ceiling, so the ratio arm is the only thing that can produce it:
	// every other case here is satisfied by a function that returns a constant
	assert.Equal(t, uint32(64*intFile.MB), maxDictionaryFor(256*intFile.KB), "a real block gets the ratio")
	assert.Equal(t, uint32(maxUPXDictionary), maxDictionaryFor(intFile.KB*512),
		"512KB is exactly where the ratio meets the ceiling")
	assert.Equal(t, uint32(maxUPXDictionary), maxDictionaryFor(1<<30), "and the ceiling caps the largest")

	// the dictionary is heap and the reconstruction is disk, so they do not share a ceiling. Sharing one
	// let the ratio alone carry a ~2MB input to a 512MB resident allocation.
	assert.Less(t, uint64(maxUPXDictionary), uint64(maxUPXOriginalSize))
	assert.Equal(t, uint32(maxUPXDictionary), maxDictionaryFor(2*intFile.MB),
		"the ratio on its own would allow 512MB here")

	// and the two ratios are separate constants so the disk one can move without moving this one
	assert.Equal(t, uint32(minUPXDictionary), maxDictionaryFor(minUPXDictionary/maxUPXDictionaryExpansion),
		"the dictionary ratio is the one that sizes this, not maxUPXExpansion")
}

func TestDecompressLZMA_UndersizedDictionaryFailsRatherThanCorrupts(t *testing.T) {
	// bounding the dictionary is only safe because getting it wrong is loud: the decoder rejects a match
	// whose distance runs past the dictionary. If that ever became a silent zero-fill, every bound keyed
	// off maxDictionaryFor would start producing plausible garbage instead of an error.
	// the first half is pseudo-random so it cannot be matched locally, and the second half repeats it, so
	// decoding the second half needs a match reaching 256KB back. A 4KB dictionary cannot serve that.
	const half = 256 * intFile.KB
	payload := make([]byte, 2*half)
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic test fixture, not a security context
	_, err := rng.Read(payload[:half])
	require.NoError(t, err)
	copy(payload[half:], payload[:half])
	stream := buildUPXLZMAStream(t, payload)

	r, err := decompressLZMA(stream, int64(len(payload)))
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err, "the honest case must still round-trip")
	require.Equal(t, payload, got)
}

func TestDecompressUPX_CompressedSizeCannotOutrunTheInput(t *testing.T) {
	// sz_cpr sizes a read buffer directly. The 24-bit mask in readBlockInfo is a field width, not a bound,
	// so on its own a ~130 byte file declaring sz_cpr = 0xFFFFFF drove a 16MB allocation that the
	// following ReadAt could only ever fail. Measured at 131,181x amplification before the bound.
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:4], 4096)       // sz_unc, inside the input-size allowance
	binary.LittleEndian.PutUint32(b[4:8], 0x00FFFFFF) // sz_cpr = 16MB-1 once masked
	b[8] = 14                                         // b_method = LZMA
	data := padTo(append(buildUPXHeader(4096, 4096), b...), 128)

	allocated := measureAlloc(t, func() {
		_, err := unpackIn(t, t.TempDir(), data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errUPXImplausibleHeader, "no block was readable, so nothing was packed")
	})
	assert.Less(t, allocated, uint64(1<<20),
		"a block claiming compressed data past the end of a 128 byte input must not be allocated for")
	t.Logf("128 byte input allocated %d bytes", allocated)
}

func TestDecompressUPX_TailExtentsArePlacedPastTheLoader(t *testing.T) {
	// with a non-zero l_lsize the chain continues past the loader stub instead of ending at the marker in
	// front of it. Every other crafted fixture here has l_lsize == 0, so without this skipLoader was only
	// reachable through the Docker-backed fixture.
	//
	// note: block 1 here is not an ELF, so there are no PT_LOAD offsets and the tail lands sequentially.
	// The hole-filling path this feeds in production is covered by TestFirstHole and by the sparse
	// fixtures in upx_bounds_regression_test.go.
	const loaderSize = 64
	head := bytes.Repeat([]byte("H"), 128)
	tail := bytes.Repeat([]byte("T"), 32)

	data := buildUPXHeaderWithLoader(4096, 4096, loaderSize)
	data = append(data, blockFor(t, head)...)
	data = append(data, make([]byte, 12)...)            // end marker: closes the first run of extents
	data = append(data, make([]byte, loaderSize-12)...) // the loader stub the chain skips over
	data = append(data, blockFor(t, tail)...)
	data = append(data, make([]byte, 12)...) // end marker for the tail run
	data = padTo(data, 1024)

	out, err := unpack(t, data)
	// 160 bytes of a declared 4096, short by construction like every other crafted fixture here
	require.ErrorIs(t, err, errUPXPartial)
	got := readAll(t, out)

	assert.Equal(t, head, got[:len(head)], "the head extent stays where it was placed")
	assert.Contains(t, string(got), string(tail), "the extent behind the loader must be placed too")
}

func TestDecompressUPX_UnsupportedMethodIsNotReportable(t *testing.T) {
	// upx defaults to NRV2B unless --lzma is passed, and only LZMA is implemented here. A packed non-Go
	// binary must not turn into an SBOM unknown from the golang cataloger, so the unsupported-method error
	// must stay clear of errUPXDecompress.
	block := make([]byte, 12)
	binary.LittleEndian.PutUint32(block[0:4], 256) // sz_unc
	binary.LittleEndian.PutUint32(block[4:8], 32)  // sz_cpr
	block[8] = 2                                   // b_method = NRV2B
	data := padTo(append(buildUPXHeader(4096, 4096), block...), 256)

	_, err := unpack(t, data)
	require.Error(t, err)
	assert.ErrorIs(t, err, errUnsupportedUPXMethod)
	assert.NotErrorIs(t, err, errUPXDecompress, "an unimplemented method is a capability gap, not a gap in the SBOM")
}

// TestUnpackUPX_QuietDirection pins the invariant the reportability policy rests on: unpackUPX is the
// layer that decides what becomes an SBOM unknown, and only errUPXDecompress, errUPXSizeRefused,
// errUPXPartial and elfutil.ErrDeclaredSizeExceeded may (see reportableGap in scan_binary.go). Everything
// else has to come back as the input with no error, so a packed non-Go binary, or one packed with a method
// we have not implemented, does not attach a golang-cataloger unknown to every such file in an image.
func TestUnpackUPX_QuietDirection(t *testing.T) {
	nrv2b := make([]byte, 12)
	binary.LittleEndian.PutUint32(nrv2b[0:4], 256) // sz_unc
	binary.LittleEndian.PutUint32(nrv2b[4:8], 32)  // sz_cpr
	nrv2b[8] = 2                                   // b_method = NRV2B, which upx emits unless --lzma

	// every fixture has to clear the ELF64 little-endian container gate, or it is turned away before the
	// magic scan and the case proves nothing about the path it names
	cases := []struct {
		name string
		data []byte
	}{
		{"a plain ELF that is not packed at all", padTo(packedELFStub(), 256)},
		{"a stray UPX magic in unrelated data", padTo(append(packedELFStub(), []byte("some string UPX! in rodata")...), 256)},
		{"a header with nothing decodable", padTo(append(buildUPXHeader(4096, 4096), make([]byte, 12)...), 256)},
		{"a method we have not implemented", padTo(append(buildUPXHeader(4096, 4096), nrv2b...), 256)},
	}
	for _, tt := range cases {
		name, data := tt.name, tt.data
		t.Run(name, func(t *testing.T) {
			ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir()))
			in := bytes.NewReader(data)
			out, err := unpackUPX(ctx, in)
			assert.NoError(t, err, "this must not become an SBOM unknown")
			assertNothingUnpacked(t, in, out)
		})
	}
}

// TestUnpackUPX_MissingTempDirIsNotReportedForEveryBinary covers the ordering that keeps a misconfigured
// context from being rendered as a per-file finding: the temp dir is only demanded once the file is known
// to be packed, so a consumer whose context carries none does not get an unknown on every executable.
func TestUnpackUPX_MissingTempDirIsNotReportedForEveryBinary(t *testing.T) {
	plain := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 256)...)

	in := bytes.NewReader(plain)
	out, err := unpackUPX(context.Background(), in)
	require.NoError(t, err, "a file that is not packed must not need a temp dir at all")
	assertNothingUnpacked(t, in, out)

	// a file that really is packed still reports, since its packages are genuinely missing
	packed := padTo(buildUPXFile(t, 4096, 4096, [][]byte{bytes.Repeat([]byte("A"), 32)}, nil), 128)
	packedIn := bytes.NewReader(packed)
	out, err = unpackUPX(context.Background(), packedIn)
	require.Error(t, err)
	assert.ErrorIs(t, err, errUPXDecompress)
	assertNothingUnpacked(t, packedIn, out, "reporting the gap must still leave the caller something to read")
}

// assertNothingUnpacked pins what a "nothing to unpack" answer owes its caller. The nil is the signal, so
// what matters is that it never reaches an interface unresolved: readerFor and seekerFor are the only two
// places allowed to widen it, and both must hand back the input as it was found.
func assertNothingUnpacked(t *testing.T, in io.ReaderAt, out *spillbuf.Buffer, msgAndArgs ...any) {
	t.Helper()
	assert.Nil(t, out, msgAndArgs...)
	assert.NoError(t, out.Close(), "Close must be safe when there is nothing to release")

	assert.Same(t, in, readerFor(out, in), "nothing to unpack means the caller reads the file as it found it")

	fallback := &nopReadSeekCloser{bytes.NewReader(nil)}
	assert.Same(t, fallback, seekerFor(out, fallback), "the seekable view falls back to the input")
}

type nopReadSeekCloser struct{ *bytes.Reader }

func (*nopReadSeekCloser) Close() error { return nil }

func TestScanReader_MaliciousUPXRejected(t *testing.T) {
	// a plausible ELF prefix so the file looks like an executable, then a UPX header whose single block
	// claims the full uint32 range. Pre-fix this reached make([]byte, 0xFFFFFFFF).
	data := append(packedELFStub(), buildUPXFile(t, 4096, 4096,
		[][]byte{bytes.Repeat([]byte("A"), 32)}, []uint32{0xFFFFFFFF})...)

	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir()))

	// go's own test timeout covers "did not return promptly"; a goroutine plus time.After here would
	// assert on an already-finished test if it ever fired.
	var build *extendedBuildInfo
	var err error
	allocated := measureAlloc(t, func() {
		build, err = scanReader(ctx, file.NewLocation("/malicious"), bytes.NewReader(data), false)
	})
	assert.Nil(t, build)
	require.Error(t, err)
	// unknown.CoordinateError does not unwrap, so reach through it to the reason it carries rather than
	// matching on the rendered message
	coordErrs, _ := unknown.ExtractCoordinateErrors(err)
	require.NotEmpty(t, coordErrs, "a packed binary we cannot unpack is worth reporting")
	assert.ErrorIs(t, coordErrs[0].Reason, errUPXDecompress)
	assert.Less(t, allocated, uint64(1<<20), "the rejection must not cost a megabyte")
}

// sizeOf is the test-side spelling of the two-value size helper, for the cases handing parseUPXInfo a
// reader whose size is obviously measurable. The not-ok direction has its own test.
func sizeOf(t *testing.T, r io.ReaderAt) int64 {
	t.Helper()
	size, ok := intFile.ReaderSize(r)
	require.True(t, ok, "the reader under test has to report a size")
	return size
}

// TestCopyUnfiltered_WindowIsNotResident is the allocation half of the unfilter tests. The others assert
// the output is byte-for-byte right, which it is with or without the window: delete the clamp in
// copyUnfiltered and every one of them still passes while a block allocates in full. One block can be most
// of a file, so the window is the only thing keeping the unfilter off the heap.
func TestCopyUnfiltered_WindowIsNotResident(t *testing.T) {
	const cto8 = 0x24
	const size = 16 * intFile.MB
	block := bytes.Repeat([]byte{0xE8, cto8, 0x11, 0x22, 0x33, 0x0F}, size/6+1)[:size]

	allocated := measureAlloc(t, func() {
		require.NoError(t, copyUnfiltered(io.Discard, bytes.NewReader(block), size, cto8))
	})

	assert.Less(t, allocated, uint64(4*upxFilterWindow),
		"unfiltering %d bytes must cost the window, not the block", size)
}

// TestDecompressUPX_CTOFilteredBlock reaches the unfilter through the block chain rather than by calling
// copyUnfiltered directly. Real `upx --best --lzma` on x86-64 sets b_ftid on every block, so this is the
// ordinary path; without it the filter, the per-block base arithmetic and the window only ever run
// together in the Docker fixture.
func TestDecompressUPX_CTOFilteredBlock(t *testing.T) {
	const cto8 = 0x24
	// the block carries the filtered form; the reconstruction is what the whole-block unfilter makes of it
	filtered := bytes.Repeat([]byte{0xE8, cto8, 0x11, 0x22, 0x33, 0x0F, 0x85, cto8, 0x44, 0x55}, 512)
	want := bytes.Clone(filtered)
	unfilter49(want, cto8, 0, true)
	require.NotEqual(t, filtered, want, "the fixture must actually be filtered")

	data := append(buildUPXHeader(uint32(len(filtered)), uint32(len(filtered))),
		filteredBlockFor(t, filtered, upxFilterCTO, cto8)...)

	out, err := unpack(t, data)
	require.NoError(t, err)
	assert.Equal(t, want, readAll(t, out), "the CTO filter must be reversed on the way out")
}

// TestUnpackUPX_ReconstructionIsRemovedOnClose pins the disk side of the temp-file contract. The cataloger
// writes one reconstruction per packed binary per scan and the cataloger's temp root is never swept, so a
// Close that stops removing turns every scanned packed binary into a leaked file.
func TestUnpackUPX_ReconstructionIsRemovedOnClose(t *testing.T) {
	dir := t.TempDir()

	// past spillbuf's memory tier on purpose: a reconstruction that fits in memory never creates a file,
	// so a small fixture here would assert the cleanup of something that was never made
	const payload = 4 * int(spillbuf.DefaultMemLimit)
	fixture := padTo(buildUPXFile(t, uint32(payload), uint32(payload), [][]byte{make([]byte, payload)}, nil),
		payload/maxUPXExpansion)

	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(dir))
	contents, err := unpackUPX(ctx, bytes.NewReader(fixture))
	require.NoError(t, err)
	require.NotNil(t, contents, "the fixture has to actually unpack for this to mean anything")

	before, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, before, "the reconstruction should be on disk while it is open")

	require.NoError(t, contents.Close())

	after, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, after, "Close has to take the reconstruction with it")
}

// TestParseUPXInfo_OnlyELF64LittleEndian pins the container gate. Everything downstream reads program
// headers at fixed ELF64 little-endian offsets, so a packed ELF32 or big-endian file would be placed by
// rules that do not apply to it, after taking a temp dir and landing as an unknown on a file this
// cataloger was never going to catalog.
func TestParseUPXInfo_OnlyELF64LittleEndian(t *testing.T) {
	// a slice rather than a map, so the subtest order is the order written here
	tests := []struct {
		name   string
		mangle func([]byte)
	}{
		{"ELF32", func(b []byte) { b[4] = 1 }},
		{"big endian", func(b []byte) { b[5] = 2 }},
		{"unset class", func(b []byte) { b[4] = 0 }},
		{"unset endian", func(b []byte) { b[5] = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := padTo(buildUPXHeader(0x1000, 0x1000), 4096)

			// control: the same fixture parses before the container byte is touched
			_, err := parseUPXInfo(bytes.NewReader(data), int64(len(data)))
			require.NoError(t, err)

			tt.mangle(data)
			_, err = parseUPXInfo(bytes.NewReader(data), int64(len(data)))
			require.Error(t, err)
			assert.ErrorIs(t, err, errNotUPX, "quiet: a container we do not reconstruct is not a gap")
		})
	}
}

// TestUnfilter49_RewritesEveryFilteredForm pins which opcodes the CTO unfilter acts on. The equivalence
// test above cannot: it compares the windowed pass against the whole-block pass through the same
// function, so dropping a form breaks both sides identically and it stays green. Only the Docker-backed
// image fixture caught it, and a regression that needs a container to detect is one CI can miss.
//
// E8 is CALL, E9 is JMP, and 0F 8x is the conditional-jump form. UPX's --lzma filter 0x49 rewrites all
// three, so a reconstruction is byte-wrong (but exactly the right length) if any of them is skipped.
func TestUnfilter49_RewritesEveryFilteredForm(t *testing.T) {
	const cto8 = 0x24

	tests := []struct {
		name  string
		instr []byte
	}{
		{name: "E8 CALL", instr: []byte{0xE8, cto8, 0x11, 0x22, 0x33}},
		{name: "E9 JMP", instr: []byte{0xE9, cto8, 0x11, 0x22, 0x33}},
		{name: "0F 85 conditional jump", instr: []byte{0x0F, 0x85, cto8, 0x11, 0x22, 0x33}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// padded so the instruction sits well inside the window the final pass evaluates
			data := append(bytes.Clone(tt.instr), bytes.Repeat([]byte{0x90}, 32)...)
			before := bytes.Clone(data)

			n := unfilter49(data, cto8, 0, true)
			require.Positive(t, n, "the pass must settle the bytes it walked")
			assert.NotEqual(t, before, data,
				"this form carries the cto marker, so the unfilter has to rewrite its operand")
		})
	}

	t.Run("an unfiltered opcode is left alone", func(t *testing.T) {
		// 0xEB is a short jump, which the filter does not touch
		data := append([]byte{0xEB, cto8, 0x11, 0x22, 0x33}, bytes.Repeat([]byte{0x90}, 32)...)
		before := bytes.Clone(data)

		unfilter49(data, cto8, 0, true)
		assert.Equal(t, before, data, "only the filtered forms may be rewritten")
	})
}

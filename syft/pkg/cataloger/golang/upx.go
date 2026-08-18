package golang

// UPX Decompression Support
//
// this file implements decompression of UPX-compressed ELF binaries to enable
// extraction of Go build information (.go.buildinfo) from packed executables.
//
// UPX (Ultimate Packer for eXecutables) is a popular executable packer that
// compresses binaries to reduce file size. When a Go binary is compressed with
// UPX, the standard debug/buildinfo.Read() fails because the .go.buildinfo
// section is compressed. This code decompresses the binary in-memory to allow
// buildinfo extraction.
//
// # Supported Compression Methods
//
// Currently only LZMA (method 14) is supported, which is used by:
//
//	upx --best --lzma <binary>
//
// Other UPX methods (NRV2B, NRV2D, NRV2E, etc.) are not yet implemented but
// could be added via the upxDecompressors dispatch map.
//
// # Key Functions
//
//   - decompressUPX: main entry point; locates the header, decompresses all blocks and reconstructs the ELF
//   - decompressLZMA: handles UPX's custom 2-byte LZMA header format
//   - unfilter49: reverses the CTO (call trick optimization) filter for x86/x64 code
//   - parseELFPTLoadOffsets: extracts PT_LOAD segment offsets for proper block placement
//
// # UPX Binary Format
//
// UPX-compressed binaries contain several header structures followed by compressed blocks:
//
//	l_info (at "UPX!" magic):
//	  - l_checksum (4 bytes before magic)
//	  - l_magic "UPX!" (4 bytes)
//	  - l_lsize (2 bytes) - loader size
//	  - l_version (1 byte)
//	  - l_format (1 byte)
//
//	p_info (12 bytes, follows l_info):
//	  - p_progid (4 bytes)
//	  - p_filesize (4 bytes) - original uncompressed file size
//	  - p_blocksize (4 bytes)
//
//	b_info (12 bytes each, one per compressed block):
//	  - sz_unc (4 bytes) - uncompressed size
//	  - sz_cpr (4 bytes) - compressed size
//	  - b_method (1 byte) - compression method (14 = LZMA)
//	  - b_ftid (1 byte) - filter ID (0x49 = CTO filter)
//	  - b_cto8 (1 byte) - filter parameter
//	  - unused (1 byte)
//
// # LZMA Header Format
//
// UPX uses a 2-byte custom header, NOT the standard 13-byte LZMA format:
//
//	Byte 0: (t << 3) | pb, where t = lc + lp
//	Byte 1: (lp << 4) | lc
//	Byte 2+: raw LZMA stream
//
// This is converted to standard LZMA props: props = lc + lp*9 + pb*9*5
//
// # ELF Segment Placement
//
// Decompressed blocks must be placed at specific file offsets according to the
// ELF PT_LOAD segments parsed from the first decompressed block. Simply
// concatenating blocks produces invalid output.
//
// # References
//
//   - UPX source: https://github.com/upx/upx
//   - LZMA format: https://github.com/upx/upx/blob/devel/src/compress/compress_lzma.cpp
//   - CTO filter: https://github.com/upx/upx/blob/master/src/filter/cto.h
//
// note: no code was copied from the UPX repo, this is an independent implementation based on format description.
//
// # Anti-Unpacking / Obfuscation (Not Currently Supported)
//
// Malware commonly modifies UPX binaries to evade analysis. This implementation
// does not currently handle obfuscated binaries, but these techniques could be
// addressed in the future:
//
//   - Magic modification: "UPX!" replaced with custom bytes (e.g., "YTS!", "MOZI").
//     Recovery: scan for decompression stub code patterns instead of magic bytes.
//
//   - Zeroed p_info fields: p_filesize and p_blocksize set to 0.
//     Recovery: read original size from PackHeader at EOF (last 36 bytes, offset 0x18).
//
//   - Header corruption: checksums or version fields modified.
//     Recovery: ignore validation and use PackHeader values as authoritative source.
//
// All of that would require parsing the PackHeader, which occupies the final 36 bytes of the file and
// carries metadata that survives a corrupted p_info. Not parsed today:
//
//	Offset  Size   Field           Description
//	──────────────────────────────────────────────────────────
//	0x00    4      UPX magic       "UPX!" (0x21585055)
//	0x04    1      version         UPX version
//	0x05    1      format          Executable format
//	0x06    1      method          Compression method
//	0x07    1      level           Compression level (1-10)
//	0x08    4      u_adler         Uncompressed data checksum
//	0x0C    4      c_adler         Compressed data checksum
//	0x10    4      u_len           Uncompressed length
//	0x14    4      c_len           Compressed length
//	0x18    4      u_file_size     Original file size  ← Recovery point
//	0x1C    1      filter          Filter ID
//	0x1D    1      filter_cto      Filter CTO parameter
//	0x1E    1      n_mru           MRU parameter
//	0x1F    1      header_checksum Header checksum
//
// Confirmed against the image-small-upx fixture, whose trailing 36 bytes decode as version=14,
// format=22, method=14 (LZMA), level=10, u_len=5811393, c_len=2966652, u_file_size=5811393,
// filter=0x49, filter_cto=0x24. Note u_file_size matches the p_filesize in p_info, and filter and
// filter_cto match the b_ftid and b_cto8 of the filtered block, so the recovery path above is real.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/ulikunitz/xz/lzma"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
)

// upxMagicScanWindow is how far into the file the "UPX!" magic is searched for. UPX places l_info
// just past the ELF headers and its loader stub, so this covers real output with room to spare.
const upxMagicScanWindow = 8192

// UPX compression method constants
const (
	upxMethodLZMA uint8 = 14 // M_LZMA in UPX source
)

// UPX filter constants
const (
	upxFilterCTO uint8 = 0x49 // CTO (call trick optimization) filter for x86/x64
)

// bounds on what a UPX header may claim before we act on it
const (
	// maxUPXOriginalSize is the absolute ceiling on p_filesize. A ratio against the input size cannot be
	// the only bound: LZMA encodes a run of N identical bytes in O(log N) bytes, so a legitimate binary
	// embedding a large compressible asset expands by hundreds of times (a `go:embed` of 120MB of zeros
	// packs to 609KB, a 209x ratio). It is the ceiling and maxUPXExpansion together that bound this.
	maxUPXOriginalSize = 500 * intFile.MB

	// maxUPXExpansion bounds p_filesize against the size of the file actually on disk, so a few dozen
	// header bytes cannot claim the absolute ceiling. Real `upx --best --lzma` output expands 1.96x on the
	// image-small-upx fixture, and the most compressible case above is 209x against the packed asset, so
	// this leaves a wide margin; the point is only that the claim has to be paid for in input bytes.
	// Applied only when the input size can be determined, otherwise the ceiling stands alone.
	maxUPXExpansion = 1024

	// maxUPXBlocks bounds the block loop. Real UPX emits one block for the ELF headers plus one per
	// PT_LOAD extent (four on the image-small-upx fixture), so single digits; this leaves room for an
	// unusual layout while keeping a file from driving unbounded iterations with minimum-size blocks.
	maxUPXBlocks = 1024

	// maxUPXLZMALiteralBits caps lc+lp. The decoder allocates and initializes a 0x300<<(lc+lp) entry
	// probability array per block, independent of block size, so the library's own ceiling of 12 costs
	// 6.3MB of stores for a one-byte block. Across maxUPXBlocks blocks that adds up, and UPX emits lc+lp
	// of 3 or less, so this stays well clear of real output while cutting the per-block cost by 16x.
	maxUPXLZMALiteralBits = 8
)

var (
	// upxMagic is the magic bytes that identify a UPX-packed binary
	upxMagic = []byte("UPX!")

	errNotUPX               = errors.New("not a UPX-compressed binary")
	errUnsupportedUPXMethod = errors.New("unsupported UPX compression method")
	errUPXOutputExceeded    = errors.New("UPX blocks decompress to more than the declared original size")
	errUPXImplausibleHeader = errors.New("implausible UPX header")
	errUPXInvalidLZMAParams = errors.New("invalid LZMA parameters")

	// errUPXDecompress marks a file that got past the header and the method dispatch and still could not
	// be unpacked, which is a gap in the SBOM rather than a file to skip. It is deliberately the only
	// signal the caller acts on: everything else this file returns (a stray magic, an implausible header,
	// a method we have not implemented) means "not something we can catalog" and stays quiet, so a new
	// guard added later is silent by default instead of turning into SBOM noise.
	errUPXDecompress = errors.New("unable to decompress UPX-compressed Go binary")
)

// upxInfo contains parsed UPX header information
type upxInfo struct {
	version       uint8
	format        uint8
	originalSize  uint32 // p_filesize - original uncompressed file size
	blockSize     uint32 // p_blocksize - size of each compression block
	firstBlockOff int64  // offset to first b_info structure
}

// blockInfo contains information about a single compressed block
type blockInfo struct {
	uncompressedSize uint32
	compressedSize   uint32
	method           uint8
	filterID         uint8
	filterCTO        uint8
	dataOffset       int64
}

// upxDecompressor decompresses compressedData into dst, which the caller has already sized to the
// block's declared uncompressed size and bounds-checked against the output buffer. Writing into a
// caller-owned slice rather than returning a fresh one is what keeps a single block from doubling
// peak memory; implementations must fill dst exactly and must not grow it.
type upxDecompressor func(compressedData, dst []byte) error

// upxDecompressors maps compression methods to their decompressor functions
var upxDecompressors = map[uint8]upxDecompressor{
	upxMethodLZMA: decompressLZMA,

	// note: the NRV algorithms are from the UCL library, an open-source implementation based on the NRV (Not Really Vanished) algorithm.
	// TODO: future methods can be added here
	// upxMethodNRV2B: decompressNRV2B,
	// upxMethodNRV2D: decompressNRV2D,
	// upxMethodNRV2E: decompressNRV2E,
}

// unfilter49 reverses UPX filter 0x49 (CTO / call trick optimization).
// The filter transforms CALL (0xE8) and JMP (0xE9) instruction addresses in x86/x64 code to improve compression.
// The filtered format stores addresses as big-endian with cto8 as the high byte marker (the `cto8` parameter,
// stored in `b_cto8`, marks transformed instructions):
//
//	original:  E8 xx xx xx xx  (CALL rel32, little-endian offset)
//	filtered:  E8 CC yy yy yy  (big-endian, CC = cto8 marker)
func unfilter49(data []byte, cto8 byte) {
	cto := uint32(cto8) << 24

	for pos := uint32(0); pos+5 <= uint32(len(data)); pos++ {
		opcode := data[pos]

		// check for E8 (CALL) or E9 (JMP)
		if opcode == 0xE8 || opcode == 0xE9 {
			// check if first byte after opcode matches cto8 marker
			if data[pos+1] == cto8 {
				// read operand as big-endian
				jc := binary.BigEndian.Uint32(data[pos+1 : pos+5])
				// subtract cto and position to get original relative address
				result := jc - (pos + 1) - cto
				// write back as little-endian
				binary.LittleEndian.PutUint32(data[pos+1:pos+5], result)
			}
		}

		// check for conditional jumps (0F 80-8F)
		if opcode == 0x0F && pos+6 <= uint32(len(data)) {
			opcode2 := data[pos+1]
			if opcode2 >= 0x80 && opcode2 <= 0x8F && data[pos+2] == cto8 {
				jc := binary.BigEndian.Uint32(data[pos+2 : pos+6])
				result := jc - (pos + 2) - cto
				binary.LittleEndian.PutUint32(data[pos+2:pos+6], result)
			}
		}
	}
}

// decompressUPX attempts to decompress a UPX-compressed ELF binary.
// It reads blocks and places them at correct file offsets based on ELF PT_LOAD segments.
//
// The first decompressed block contains the original ELF headers. Parse them to get PT_LOAD segment
// file offsets for proper block placement:
//
//   - After decompressing block 1, parse its ELF headers:
//     ptLoadOffsets := parseELFPTLoadOffsets(block1Data)
//
// - Block 1: placed at offset 0 (contains ELF header + program headers)
// - Block 2: placed immediately after block 1 (running outputOffset, not offset 0)
// - Block 3+: placed at ptLoadOffsets[blockNum-2]
//
// Why this matters: simply concatenating decompressed blocks produces invalid output.
// Each block corresponds to a PT_LOAD segment and must be placed at its correct file offset.
//
// Returns the decompressed binary as a bytes.Reader (implements io.ReaderAt). errNotUPX and
// errUPXImplausibleHeader mean the file is not really packed; only errUPXDecompress means a packed file
// we could not read.
func decompressUPX(r io.ReaderAt) (io.ReaderAt, error) {
	info, err := parseUPXInfo(r)
	if err != nil {
		return nil, err
	}

	output, err := decompressUPXBlocks(r, info)
	if err != nil {
		return nil, err
	}
	if output == nil {
		// a plausible header with nothing decodable behind it is not a packed binary
		return nil, fmt.Errorf("%w: no decodable blocks", errUPXImplausibleHeader)
	}

	return bytes.NewReader(output), nil
}

// decompressUPXBlocks walks the b_info chain, decoding each block into its place in the reconstructed
// file. It returns nil (with a nil error) when no block survived validation. A short or malformed chain
// yields the blocks placed so far rather than an error, since those are often enough to recover
// .go.buildinfo; only a block that claims more output than the header allows, or one that fails to
// decode, fails the file.
func decompressUPXBlocks(r io.ReaderAt, info *upxInfo) ([]byte, error) {
	// output is allocated on the first block that survives validation rather than up front, so a header
	// that claims a large p_filesize but carries no decodable block costs nothing. It is the dominant
	// allocation on this path, bounded by parseUPXInfo. Blocks decode directly into slices of it rather
	// than into a per-block buffer that is then copied, which keeps a single block from doubling peak
	// memory. Also live during a decode: the LZMA decoder's dictionary (up to 128MB, see maxDictSize) and
	// the compressed block being read.
	var output []byte

	// UPX packs the original file as a series of blocks that together reconstruct p_filesize. Track the
	// unclaimed remainder so the block headers cannot drive more decompression than the file itself
	// declares: without this, every block may individually claim the whole original size, and the total
	// work becomes (block count x original size). This is the bound that does the real work here.
	remaining := info.originalSize

	currentOffset := info.firstBlockOff
	outputOffset := uint64(0)
	blockNum := 0
	var ptLoadOffsets []uint64

	for blockNum < maxUPXBlocks {
		block, err := readBlockInfo(r, currentOffset)
		if err != nil {
			// a real UPX file runs out of b_info structures before it runs out of blocks: the bytes after
			// the last block are the loader stub, not another header. Keep what is placed so far.
			log.WithFields("block", blockNum+1, "offset", currentOffset, "error", err).
				Trace("UPX block info unreadable, using partial output")
			break
		}
		if block.uncompressedSize == 0 {
			break // end marker
		}

		// an unknown method on the first block means we cannot read this file at all; on a later block it
		// marks the end of the block chain, since the trailing loader bytes are not a b_info.
		decompressor, ok := upxDecompressors[block.method]
		if !ok {
			if blockNum == 0 {
				return nil, fmt.Errorf("%w: method %d", errUnsupportedUPXMethod, block.method)
			}
			break
		}

		// the blocks together reconstruct p_filesize, so the running remainder bounds the total output.
		// Deliberately the only size check on a block: comparing sz_unc against p_blocksize as well adds
		// nothing here (remaining is already <= p_filesize) and real output sits at exactly p_blocksize,
		// so that check would run with no headroom against a value the format does not guarantee.
		if block.uncompressedSize > remaining {
			return nil, fmt.Errorf("%w: %w: block %d claims %d with %d left of %d", errUPXDecompress,
				errUPXOutputExceeded, blockNum+1, block.uncompressedSize, remaining, info.originalSize)
		}
		remaining -= block.uncompressedSize
		blockNum++

		if output == nil {
			output = make([]byte, info.originalSize)
		}

		// blocks 1 and 2 run sequentially; blocks 3+ go to their PT_LOAD segment offset
		destOffset := outputOffset
		if blockNum > 2 && len(ptLoadOffsets) > blockNum-2 {
			destOffset = ptLoadOffsets[blockNum-2]
		}

		dst, ok := blockDest(output, destOffset, block.uncompressedSize)
		if !ok {
			// the file does not describe the layout it claims. Keep the blocks placed so far, but stop:
			// outputOffset derives from destOffset, so continuing would carry the bad offset forward.
			log.WithFields("block", blockNum, "offset", destOffset, "outputSize", len(output)).
				Trace("UPX block placement out of range, using partial output")
			break
		}

		if err := decompressBlock(r, block, decompressor, dst); err != nil {
			return nil, fmt.Errorf("%w: %w", errUPXDecompress, err)
		}

		// the first block carries the original ELF headers, which place every block after the second
		if blockNum == 1 {
			ptLoadOffsets = parseELFPTLoadOffsets(dst)
		}

		outputOffset = destOffset + uint64(block.uncompressedSize)
		currentOffset = block.dataOffset + int64(block.compressedSize)
	}

	if blockNum == maxUPXBlocks {
		// truncated output, not a failure: the blocks placed so far may still carry .go.buildinfo. Logged
		// because a legitimate file this far outside real UPX layout is worth knowing about.
		log.WithFields("blocks", blockNum).Trace("UPX block count hit the cap, using partial output")
	}

	return output, nil
}

// blockDest returns the slice of output that a block of the given size occupies at destOffset, or false
// if it does not fit. destOffset comes from an ELF p_offset in the file, so the check is written as a
// subtraction to keep a uint64 overflow from slipping an out-of-range offset past destOffset+size. The
// result is capped to its own length so a decompressor that appends cannot reach the next block's region.
func blockDest(output []byte, destOffset uint64, size uint32) ([]byte, bool) {
	outLen := uint64(len(output))
	if destOffset > outLen || uint64(size) > outLen-destOffset {
		return nil, false
	}
	end := destOffset + uint64(size)
	return output[destOffset:end:end], true
}

// decompressBlock reads one block's compressed data and decodes it into dst, reversing the CTO filter
// if the block declares one.
func decompressBlock(r io.ReaderAt, block *blockInfo, decompressor upxDecompressor, dst []byte) error {
	compressedData := make([]byte, block.compressedSize)
	if _, err := r.ReadAt(compressedData, block.dataOffset); err != nil {
		return fmt.Errorf("failed to read compressed data: %w", err)
	}

	if err := decompressor(compressedData, dst); err != nil {
		return fmt.Errorf("failed to decompress block: %w", err)
	}

	if block.filterID == upxFilterCTO {
		unfilter49(dst, block.filterCTO)
	}
	return nil
}

// parseELFPTLoadOffsets extracts PT_LOAD segment file offsets from ELF headers.
// These offsets determine where each decompressed block should be placed.
func parseELFPTLoadOffsets(elfHeader []byte) []uint64 {
	if len(elfHeader) < 64 {
		return nil
	}

	// verify ELF magic
	if !bytes.HasPrefix(elfHeader, []byte{0x7f, 'E', 'L', 'F'}) {
		return nil
	}

	// only support 64-bit ELF
	if elfHeader[4] != 2 {
		return nil
	}

	// parse ELF64 header fields
	phoff := binary.LittleEndian.Uint64(elfHeader[0x20:0x28])
	phentsize := binary.LittleEndian.Uint16(elfHeader[0x36:0x38])
	phnum := binary.LittleEndian.Uint16(elfHeader[0x38:0x3a])

	const elf64PhdrSize = 56 // fixed size of an ELF64 program header entry

	// the reads below use fixed offsets up to byte 16 of each entry, so a shorter entry must not be
	// accepted. Loop-invariant, so it is checked once here rather than per iteration.
	if phentsize < elf64PhdrSize {
		return nil
	}

	hdrLen := uint64(len(elfHeader))
	var offsets []uint64
	for i := range phnum {
		phStart := phoff + uint64(i)*uint64(phentsize)
		// subtraction form so a large phoff cannot overflow phStart+phentsize past the buffer end.
		// note: the `break` is load-bearing for that argument. It guarantees phoff <= hdrLen before any
		// i >= 1 is reached, which is what keeps phStart itself from wrapping; a `continue` here would
		// let phoff near 2^64 wrap into a small in-range phStart and read a bogus p_offset.
		if phStart > hdrLen || hdrLen-phStart < uint64(phentsize) {
			break
		}

		ph := elfHeader[phStart:]
		ptype := binary.LittleEndian.Uint32(ph[0:4])

		// PT_LOAD = 1
		if ptype == 1 {
			poffset := binary.LittleEndian.Uint64(ph[8:16])
			offsets = append(offsets, poffset)
		}
	}

	return offsets
}

// inputSize reports the size of the file behind r, or 0 if it cannot be determined. Both *bytes.Reader
// and *io.SectionReader answer directly; the UnionReader that reaches this path in a real scan only has
// Seek, so fall back to a save-and-restore seek.
func inputSize(r io.ReaderAt) int64 {
	if sr, ok := r.(interface{ Size() int64 }); ok {
		return sr.Size()
	}
	s, ok := r.(io.Seeker)
	if !ok {
		return 0
	}
	cur, err := s.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0
	}
	size, err := s.Seek(0, io.SeekEnd)
	if err != nil {
		return 0
	}
	if _, err := s.Seek(cur, io.SeekStart); err != nil {
		return 0
	}
	return size
}

// maxOriginalSize is the ceiling p_filesize may claim for this input: the absolute cap, further limited
// by what the bytes on disk can plausibly expand to. A header only a few dozen bytes long must not be
// able to claim the absolute cap, since p_filesize sizes the output buffer directly.
func maxOriginalSize(r io.ReaderAt) uint64 {
	size := inputSize(r)
	if size <= 0 {
		// no size available, so the absolute ceiling is all we have
		return maxUPXOriginalSize
	}
	return min(uint64(size)*maxUPXExpansion, maxUPXOriginalSize)
}

// parseUPXInfo locates and parses the UPX header information
func parseUPXInfo(r io.ReaderAt) (*upxInfo, error) {
	buf := make([]byte, upxMagicScanWindow)
	n, err := r.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	magicIdx := bytes.Index(buf[:n], upxMagic)
	if magicIdx == -1 {
		return nil, errNotUPX
	}

	// UPX header structure (after finding "UPX!" magic):
	// l_info structure (magic is at offset 4 within l_info):
	//   offset -4: l_checksum (4 bytes) - checksum of following data
	//   offset 0:  l_magic "UPX!" (4 bytes)
	//   offset 4:  l_lsize (2 bytes) - loader size
	//   offset 6:  l_version (1 byte)
	//   offset 7:  l_format (1 byte)
	//
	// p_info structure (12 bytes, starts at magic+8):
	//   offset 0: p_progid (4 bytes)
	//   offset 4: p_filesize (4 bytes) - original file size
	//   offset 8: p_blocksize (4 bytes)
	//
	// b_info structures follow (12 bytes each) and are read via ReadAt, not from buf:
	//   offset 0: sz_unc (4 bytes) - uncompressed size of this block
	//   offset 4: sz_cpr (4 bytes) - compressed size (may have filter bits)
	//   offset 8: b_method (1 byte)
	//   offset 9: b_ftid (1 byte) - filter id
	//   offset 10: b_cto8 (1 byte) - filter parameter
	//   offset 11: unused (1 byte)

	// the reads below reach magic+20 (the end of p_info); b_info comes from ReadAt later. Wrapped as an
	// implausible header rather than its own error so the caller keeps treating it as "not really UPX".
	const lInfoAndPInfoSize = 20
	if magicIdx+lInfoAndPInfoSize > n {
		return nil, fmt.Errorf("%w: header runs past the end of the scan window", errUPXImplausibleHeader)
	}

	lInfoBase := buf[magicIdx:]
	pInfoBase := buf[magicIdx+8:] // p_info starts 8 bytes after magic

	info := &upxInfo{
		version:       lInfoBase[6],
		format:        lInfoBase[7],
		originalSize:  binary.LittleEndian.Uint32(pInfoBase[4:8]),
		blockSize:     binary.LittleEndian.Uint32(pInfoBase[8:12]),
		firstBlockOff: int64(magicIdx + 8 + 12), // magic + l_info remainder + p_info
	}

	// the magic is found by an unanchored substring scan, so a stray "UPX!" in unrelated data (e.g. a
	// string constant) can be read as a header. These checks are false-positive suppression, not
	// hardening: the fields are attacker-controlled, and what actually bounds the work is the size limit
	// below plus the running remainder in decompressUPX.
	if info.version == 0 || info.format == 0 {
		// l_version is the packheader version (11-14 in the wild) and l_format is a UPX_F_* id starting
		// at 1, so neither is ever zero in real output.
		return nil, fmt.Errorf("%w: version=%d format=%d", errUPXImplausibleHeader, info.version, info.format)
	}
	// p_blocksize is only checked for being set; it is not used as a bound. UPX derives it from a PT_LOAD
	// extent, and on real output the largest block equals it exactly, so treating it as a ceiling on
	// sz_unc would run with zero headroom against a value the format does not actually promise.
	if info.blockSize == 0 {
		return nil, fmt.Errorf("%w: p_blocksize is zero", errUPXImplausibleHeader)
	}
	// p_filesize sizes the output buffer, so this is the bound that matters most on this path
	limit := maxOriginalSize(r)
	if info.originalSize == 0 || uint64(info.originalSize) > limit {
		return nil, fmt.Errorf("%w: p_filesize %d exceeds the %d byte limit for a %d byte input",
			errUPXImplausibleHeader, info.originalSize, limit, inputSize(r))
	}

	return info, nil
}

// readBlockInfo reads a b_info structure at the given offset
func readBlockInfo(r io.ReaderAt, offset int64) (*blockInfo, error) {
	buf := make([]byte, 12)
	_, err := r.ReadAt(buf, offset)
	if err != nil {
		return nil, err
	}

	szUnc := binary.LittleEndian.Uint32(buf[0:4])
	szCpr := binary.LittleEndian.Uint32(buf[4:8])

	// note: the high 8 bits of sz_cpr are masked off because some UPX formats store flags there. For the
	// ELF format this code handles, filter data lives in b_ftid/b_cto8 instead, so the mask only matters
	// for a block whose compressed size exceeds 16MB, where it would truncate the read. Not a size bound.
	block := &blockInfo{
		uncompressedSize: szUnc,
		compressedSize:   szCpr & 0x00ffffff, // lower 24 bits
		method:           buf[8],
		filterID:         buf[9],
		filterCTO:        buf[10],
		dataOffset:       offset + 12, // data starts right after b_info
	}

	return block, nil
}

// nextPowerOf2 returns the smallest power of 2 >= n, saturating at 2^31 rather than overflowing to 0, so
// the result is not >= n for n above 2^31. The saturation is unreachable from the only caller (dst is
// bounded by p_filesize, far below 2^31); it is here so the helper is not a trap if reused.
func nextPowerOf2(n uint32) uint32 {
	if n == 0 {
		return 1
	}
	// if already a power of 2, return it
	if n&(n-1) == 0 {
		return n
	}
	if n > 1<<31 {
		return 1 << 31
	}
	// find the highest set bit and shift left by 1
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	return n + 1
}

// decompressLZMA decompresses LZMA-compressed data as used by UPX.
// UPX uses a 2-byte custom header format, not the standard 13-byte LZMA format.
//
// UPX 2-byte header encoding:
//   - Byte 0: (t << 3) | pb, where t = lc + lp
//   - Byte 1: (lp << 4) | lc
//   - Byte 2+: raw LZMA stream (starts with 0x00 for range decoder init)
//
// Standard LZMA props encoding: props = lc + lp*9 + pb*9*5
func decompressLZMA(compressedData, dst []byte) error {
	if len(compressedData) < 3 {
		return errors.New("compressed data too short")
	}

	// parse UPX's 2-byte LZMA header
	pb := compressedData[0] & 0x07
	lp := compressedData[1] >> 4
	lc := compressedData[1] & 0x0f

	// the header nibbles can hold values outside the LZMA ranges. This is a correctness check, not a
	// bound: the library derives lc/lp/pb back out of the props byte by modular arithmetic, so it cannot
	// be handed an out-of-range value. What it prevents is the uint8 math below wrapping (lc=15, lp=15,
	// pb=7 gives 465, which truncates to 209) and silently decoding with parameters that never existed.
	// lc+lp is capped separately, and that one is about allocation: see maxUPXLZMALiteralBits.
	if lc > 8 || lp > 4 || pb > 4 {
		return fmt.Errorf("%w: lc=%d lp=%d pb=%d", errUPXInvalidLZMAParams, lc, lp, pb)
	}
	if uint16(lc)+uint16(lp) > maxUPXLZMALiteralBits {
		return fmt.Errorf("%w: lc+lp=%d exceeds %d", errUPXInvalidLZMAParams, lc+lp, maxUPXLZMALiteralBits)
	}

	// convert to standard LZMA properties byte
	props := lc + lp*9 + pb*9*5

	// raw LZMA stream starts at byte 2 (includes 0x00 init byte)
	lzmaStream := compressedData[2:]

	uncompressedSize := uint32(len(dst))

	// compute dictionary size: must be at least as large as uncompressed size
	// use next power of 2 for efficiency, with reasonable min/max bounds.
	// note: if you're seeing that testing small binaries works and large ones don't,
	// it may be that the dictionary size was not considered properly in this code.
	const minDictSize = 64 * 1024         // 64KB minimum
	const maxDictSize = 128 * 1024 * 1024 // 128MB maximum
	dictSize := min(max(nextPowerOf2(uncompressedSize), minDictSize), maxDictSize)

	// construct standard 13-byte LZMA header
	header := make([]byte, 13)
	header[0] = props
	binary.LittleEndian.PutUint32(header[1:5], dictSize)
	binary.LittleEndian.PutUint64(header[5:13], uint64(uncompressedSize))

	// MultiReader rather than concatenating, so the compressed block is not copied a second time
	reader, err := lzma.NewReader(io.MultiReader(bytes.NewReader(header), bytes.NewReader(lzmaStream)))
	if err != nil {
		return fmt.Errorf("failed to create LZMA reader: %w", err)
	}

	// dst is a slice of the caller's output buffer, sized to the block's declared uncompressed size
	if _, err := io.ReadFull(reader, dst); err != nil {
		return fmt.Errorf("failed to decompress LZMA data: %w", err)
	}

	return nil
}

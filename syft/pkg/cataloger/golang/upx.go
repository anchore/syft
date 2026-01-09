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
//   - isUPXCompressed: detects UPX magic bytes ("UPX!") in the binary
//   - decompressUPX: main entry point; decompresses all blocks and reconstructs the ELF
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
// This would require parsing of the PackHeader, located in the final 36 bytes of the file, contains
// metadata recoverable even if p_info is corrupted (not parsed today):
//
//   Offset  Size   Field           Description
//   ──────────────────────────────────────────────────────────
//   0x00    4      UPX magic       "UPX!" (0x21585055)
//   0x04    1      version         UPX version
//   0x05    1      format          Executable format
//   0x06    1      method          Compression method
//   0x07    1      level           Compression level (1-10)
//   0x08    4      u_adler         Uncompressed data checksum
//   0x0C    4      c_adler         Compressed data checksum
//   0x10    4      u_len           Uncompressed length
//   0x14    4      c_len           Compressed length
//   0x18    4      u_file_size     Original file size  ← Recovery point
//   0x1C    1      filter          Filter ID
//   0x1D    1      filter_cto      Filter CTO parameter
//   0x1E    1      n_mru           MRU parameter
//   0x1F    1      header_checksum Header checksum

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

// UPX compression method constants
const (
	upxMethodLZMA uint8 = 14 // M_LZMA in UPX source
)

// UPX filter constants
const (
	upxFilterCTO uint8 = 0x49 // CTO (call trick optimization) filter for x86/x64
)

var (
	// upxMagic is the magic bytes that identify a UPX-packed binary
	upxMagic = []byte("UPX!")

	errNotUPX               = errors.New("not a UPX-compressed binary")
	errUnsupportedUPXMethod = errors.New("unsupported UPX compression method")
)

// upxInfo contains parsed UPX header information
type upxInfo struct {
	magicOffset   int64
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

// upxDecompressor is a function that decompresses data using a specific method
type upxDecompressor func(compressedData []byte, uncompressedSize uint32) ([]byte, error)

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

// isUPXCompressed checks if the reader contains a UPX-compressed binary
func isUPXCompressed(r io.ReaderAt) bool {
	// UPX magic can be at various offsets depending on the binary format
	// scan the first 4KB for the magic bytes
	buf := make([]byte, 4096)
	n, err := r.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	return bytes.Contains(buf[:n], upxMagic)
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
// - Block 2: placed at offset 0 (overwrites/extends)
// - Block 3+: placed at ptLoadOffsets[blockNum-2]
//
// Why this matters: Simply concatenating decompressed blocks produces invalid output.
// Each block corresponds to a PT_LOAD segment and must be placed at its correct file offset.
//
// Returns the decompressed binary as a bytes.Reader (implements io.ReaderAt).
func decompressUPX(r io.ReaderAt) (io.ReaderAt, error) {
	info, err := parseUPXInfo(r)
	if err != nil {
		return nil, err
	}

	// allocate buffer for the full decompressed output
	output := make([]byte, info.originalSize)

	currentOffset := info.firstBlockOff
	outputOffset := uint64(0)
	blockNum := 0

	// track PT_LOAD segment offsets for proper block placement
	var ptLoadOffsets []uint64

	for {
		block, err := readBlockInfo(r, currentOffset)
		if err != nil {
			return nil, fmt.Errorf("failed to read block info at offset %d: %w", currentOffset, err)
		}

		// check for end marker (sz_unc == 0)
		if block.uncompressedSize == 0 {
			break
		}

		// non-LZMA method on first block is an error; on subsequent blocks it indicates end of data
		if block.method != upxMethodLZMA {
			if blockNum == 0 {
				return nil, fmt.Errorf("%w: method %d", errUnsupportedUPXMethod, block.method)
			}
			break
		}
		blockNum++

		decompressor, ok := upxDecompressors[block.method]
		if !ok {
			return nil, fmt.Errorf("%w: method %d", errUnsupportedUPXMethod, block.method)
		}

		// read compressed data for this block
		compressedData := make([]byte, block.compressedSize)
		_, err = r.ReadAt(compressedData, block.dataOffset)
		if err != nil {
			return nil, fmt.Errorf("failed to read compressed data: %w", err)
		}

		// decompress this block
		blockData, err := decompressor(compressedData, block.uncompressedSize)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress block: %w", err)
		}

		// apply CTO filter reversal if needed
		if block.filterID == upxFilterCTO {
			unfilter49(blockData, block.filterCTO)
		}

		// first block contains ELF headers - parse PT_LOAD segments for subsequent blocks
		if blockNum == 1 {
			ptLoadOffsets = parseELFPTLoadOffsets(blockData)
		}

		// determine where to place this block in the output
		destOffset := outputOffset
		if blockNum > 2 && len(ptLoadOffsets) > blockNum-2 {
			// blocks 3+ go to their respective PT_LOAD segment offsets
			destOffset = ptLoadOffsets[blockNum-2]
		}

		// copy block data to output at correct offset
		if destOffset+uint64(len(blockData)) <= uint64(len(output)) {
			copy(output[destOffset:], blockData)
		}

		outputOffset = destOffset + uint64(block.uncompressedSize)
		currentOffset = block.dataOffset + int64(block.compressedSize)
	}

	return bytes.NewReader(output), nil
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

	var offsets []uint64
	for i := uint16(0); i < phnum; i++ {
		phStart := phoff + uint64(i)*uint64(phentsize)
		if phStart+uint64(phentsize) > uint64(len(elfHeader)) {
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

// parseUPXInfo locates and parses the UPX header information
func parseUPXInfo(r io.ReaderAt) (*upxInfo, error) {
	// scan for the UPX! magic in the first 8KB
	buf := make([]byte, 8192)
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
	// b_info structures follow (12 bytes each):
	//   offset 0: sz_unc (4 bytes) - uncompressed size of this block
	//   offset 4: sz_cpr (4 bytes) - compressed size (may have filter bits)
	//   offset 8: b_method (1 byte)
	//   offset 9: b_ftid (1 byte) - filter id
	//   offset 10: b_cto8 (1 byte) - filter parameter
	//   offset 11: unused (1 byte)

	if magicIdx+32 > n {
		return nil, fmt.Errorf("UPX header truncated")
	}

	lInfoBase := buf[magicIdx:]
	pInfoBase := buf[magicIdx+8:] // p_info starts 8 bytes after magic

	info := &upxInfo{
		magicOffset:   int64(magicIdx),
		version:       lInfoBase[6],
		format:        lInfoBase[7],
		originalSize:  binary.LittleEndian.Uint32(pInfoBase[4:8]),
		blockSize:     binary.LittleEndian.Uint32(pInfoBase[8:12]),
		firstBlockOff: int64(magicIdx + 8 + 12), // magic + l_info remainder + p_info
	}

	// sanity check
	if info.originalSize == 0 || info.originalSize > 500*1024*1024 {
		return nil, fmt.Errorf("invalid original size: %d", info.originalSize)
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

	// the compressed size may have filter info in the high bits
	// for some formats, but for LZMA it's typically clean
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

// nextPowerOf2 returns the smallest power of 2 >= n
func nextPowerOf2(n uint32) uint32 {
	if n == 0 {
		return 1
	}
	// if already a power of 2, return it
	if n&(n-1) == 0 {
		return n
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
func decompressLZMA(compressedData []byte, uncompressedSize uint32) ([]byte, error) {
	if len(compressedData) < 3 {
		return nil, fmt.Errorf("compressed data too short")
	}

	// parse UPX's 2-byte LZMA header
	pb := compressedData[0] & 0x07
	lp := compressedData[1] >> 4
	lc := compressedData[1] & 0x0f

	// convert to standard LZMA properties byte
	props := lc + lp*9 + pb*9*5

	// raw LZMA stream starts at byte 2 (includes 0x00 init byte)
	lzmaStream := compressedData[2:]

	// compute dictionary size: must be at least as large as uncompressed size
	// use next power of 2 for efficiency, with reasonable min/max bounds.
	// note: if you're seeing that testing small binaries works and large ones don't,
	// it may be that the dictionary size was not considered properly in this code.
	const minDictSize = 64 * 1024         // 64KB minimum
	const maxDictSize = 128 * 1024 * 1024 // 128MB maximum
	dictSize := nextPowerOf2(uncompressedSize)
	if dictSize < minDictSize {
		dictSize = minDictSize
	}
	if dictSize > maxDictSize {
		dictSize = maxDictSize
	}

	// construct standard 13-byte LZMA header
	header := make([]byte, 13)
	header[0] = props //nolint:gosec
	binary.LittleEndian.PutUint32(header[1:5], dictSize)
	binary.LittleEndian.PutUint64(header[5:13], uint64(uncompressedSize))

	// combine header + raw stream
	var fullStream []byte
	fullStream = append(fullStream, header...)
	fullStream = append(fullStream, lzmaStream...)

	reader, err := lzma.NewReader(bytes.NewReader(fullStream))
	if err != nil {
		return nil, fmt.Errorf("failed to create LZMA reader: %w", err)
	}

	decompressed := make([]byte, uncompressedSize)
	_, err = io.ReadFull(reader, decompressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress LZMA data: %w", err)
	}

	return decompressed, nil
}

package golang

// UPX Decompression Support
//
// this file reconstructs UPX-compressed ELF binaries so the scan reads unpacked contents: .go.buildinfo,
// the pclntab, version strings and the machine type all come from the reconstruction.
//
// The reconstruction goes through a spillbuf.Buffer rather than a []byte: it holds a bounded amount in
// memory and spills the rest to disk, since its size is declared by the file being read and a claim that
// cannot be trusted with the heap can still be trusted with the disk. Blocks stream into it through a fixed
// window, so a single large block is never resident in full either.
//
// Disk still needs a ceiling, so the bounds below are both a ratio against what the input brought with it
// and an absolute cap: a ratio alone is cheap to defeat, since image layers are gzipped and 16MB of zeros
// costs ~16KB, and the file cataloger runs NumCPU*4 of these at once.
//
// The reader handed back is sized by the contiguous bytes actually rebuilt, not by where the last block
// landed. A sparse file serves its holes as zeros it never stored, so a block's offset would otherwise be
// an allocation knob for every parser downstream that sizes against what a reader will deliver.
//
// Only LZMA (method 14, what `upx --best --lzma` emits) and stored blocks are implemented; other methods
// can be added to upxDecompressors.
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
// Those extents cover only the loadable segments. Behind the loader stub (l_lsize in l_info) UPX packs
// what they did not: the padding between segments and the non-loadable tail holding the section headers
// and name table. Without that tail there are no readable section names, so .gopclntab cannot be found and
// no symbols come out. Those extents fill the gaps in file order.
//
// # References
//
//   - UPX source: https://github.com/upx/upx
//   - LZMA format: https://github.com/upx/upx/blob/devel/src/compress/compress_lzma.cpp
//   - CTO filter: https://github.com/upx/upx/blob/master/src/filter/cto.h
//
// note: no code was copied from the UPX repo, this is an independent implementation based on format description.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/ulikunitz/xz/lzma"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/spillbuf"
	"github.com/anchore/syft/internal/tmpdir"
)

// upxMagicScanWindow is how far into the file the "UPX!" magic is searched for. UPX places l_info
// just past the ELF headers and its loader stub, so this covers real output with room to spare.
const upxMagicScanWindow = 8192

// UPX compression method constants
const (
	upxMethodLZMA uint8 = 14 // M_LZMA in UPX source

	// upxMethodStored marks an extent UPX could not compress and wrote verbatim. Real output carries a few
	// of these: the alignment padding between PT_LOAD segments is only a handful of bytes.
	upxMethodStored uint8 = 0
)

// UPX filter constants
const (
	upxFilterCTO uint8 = 0x49 // CTO (call trick optimization) filter for x86/x64
)

// bounds on what a UPX header may claim before we act on it
const (
	// maxUPXExpansion bounds p_filesize against the bytes the input actually brought with it. Real
	// `upx --best --lzma` output expands 1.96x, and the most compressible case measured is 209x (a
	// `go:embed` of 120MB of zeros packs to 609KB), so 256 clears anything real without much headroom.
	maxUPXExpansion = 256

	// maxUPXDictionaryExpansion is the same shape of ratio for the LZMA dictionary, which is heap rather
	// than disk. Deliberately its own constant even at the same value: raising the disk ratio for a
	// legitimately compressible binary must not multiply a per-block heap allocation by the same factor.
	maxUPXDictionaryExpansion = 256

	// maxUPXOriginalSize is the absolute ceiling the ratio cannot supply on its own, since padding an
	// input is nearly free. 512MB is 4x the largest legitimate original measured (121MB).
	//
	// This is not a disk-only figure. The reconstruction is truncated to what was actually rebuilt, which
	// is what makes a hole stop being an allocation knob, but the bytes inside that prefix are real and
	// downstream sizes against them: saferio in debug/elf grows an uncompressed section until the reader
	// stops delivering, so a section declaring the whole reconstruction allocates it. elfutil bounds a
	// section that declares a *decompressed* size at 128MB; this is the bound on the other kind.
	//
	// It is deliberately not matched to elfutil's 128MB, because this ceiling is not what stands between
	// an attacker and that allocation: scanFile applies no size ceiling of any kind to an *unpacked*
	// binary, so a plain padded 512MB ELF reaches the same saferio growth through the same
	// getCryptoInformation call at the same cost to build. Lowering this number would refuse legitimate
	// packed binaries between 128MB and 512MB and leave that path untouched. Bounding an uncompressed
	// section against the reader's real length in elfutil is what would actually close it, and that is a
	// change for the sibling catalogers as much as this one.
	//
	// So the job here is narrower than it looks: keep the ratio from being the only thing standing behind
	// p_filesize, since padding an input is nearly free.
	//
	// Per file, with no shared budget across the cataloger's NumCPU*4 concurrent unpacks.
	maxUPXOriginalSize = 512 * intFile.MB

	// maxUPXDictionary is the ceiling on the LZMA dictionary, which unlike the reconstruction is resident.
	// Matched to elfutil.maxDeclaredSectionSize, the same kind of bound in the sibling ELF path.
	//
	// Unlike the others this binds on absolute block size rather than on a ratio, so it is also a known
	// functional ceiling: a single block whose sz_unc runs past it decodes only while its match distances
	// stay inside the dictionary. A ~200MB single-block binary can therefore fail to decode, which ends
	// the chain and is reported as a partial reconstruction rather than dropped. Raising it multiplies the
	// worst-case resident cost by the cataloger's concurrency, which is why it has not been raised.
	maxUPXDictionary = 128 * intFile.MB

	// minUPXDictionary is the floor. The decoder needs a dictionary at all, and a block small enough to
	// sit under it costs nothing to be generous with.
	minUPXDictionary = 64 * intFile.KB

	// maxUPXBlocks bounds the block loop. Real UPX emits one block for the ELF headers plus one per
	// PT_LOAD extent (four on the image-small-upx fixture), so single digits; this leaves room for an
	// unusual layout while keeping a file from driving unbounded iterations with minimum-size blocks.
	maxUPXBlocks = 1024

	// upxFilterWindow is the working set of the CTO unfilter. The filter is a forward scan needing only a
	// few bytes of lookahead, so it does not need its block resident, and one block can be most of a file.
	upxFilterWindow = intFile.MB

	// upxELFHeaderWindow bounds how much of the first block is read back to find the PT_LOAD offsets that
	// place the later blocks. The program headers of a real ELF64 start at byte 64.
	upxELFHeaderWindow = 64 * intFile.KB

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

	// errUPXSizeRefused is a header that really is UPX and claims more than the bounds allow. Unlike the
	// implausible-header cases (a stray "UPX!" in a string constant), this is a file we declined to expand
	// rather than a file that was never packed, so it is reported as an unknown the way
	// elfutil.ErrDeclaredSizeExceeded is. The ratio clears a measured 209x worst case at 256, which is not
	// much headroom, and a binary silently vanishing from the SBOM is the failure this avoids.
	//
	// Reported conditionally: nothing was unpacked when this fires, so if the bytes as they were found turn
	// out to carry build info then the file was never really packed and there is no gap. See
	// readContentsAndBuildInfo.
	errUPXSizeRefused       = errors.New("UPX header claims more than the bounds allow")
	errUPXInvalidLZMAParams = errors.New("invalid LZMA parameters")

	// errUPXPartial marks a reconstruction that really is UPX and really did decode, but gave something
	// up on the way: a chain that stopped early, a block that would not decode, or blocks placed past a
	// gap the chain never filled. The contents come back readable and usable, since .go.buildinfo and the
	// pclntab live in the early extents, but the bytes past the covered prefix are gone. That is a gap
	// this cataloger chose to leave, so it is reported the same way errUPXSizeRefused is: without it a
	// short chain drops the section-name table and the binary silently contributes nothing.
	//
	// Reported unconditionally, unlike errUPXSizeRefused below: a partial only exists when there really is
	// a reconstruction, so the "nothing was unpacked, so nothing is short" suppression in
	// readContentsAndBuildInfo cannot apply to it.
	//
	// Its population is wider than just packed Go binaries, and that is accepted rather than overlooked.
	// The block placement rules are ELF and Go-shaped, so a --lzma-packed non-Go ELF whose layout they do
	// not tile ends here too, and bi == nil cannot tell that apart from a packed Go binary whose
	// reconstruction lost .go.buildinfo, which is the case this exists to report. It stays reportable
	// because the population is far narrower than the errUnsupportedUPXMethod carve-out below: upx emits
	// NRV2B by default, so most packed binaries in an image never reach a block placement at all.
	errUPXPartial = errors.New("UPX reconstruction is incomplete")

	// errUPXDecompress marks a file that got past the header and the method dispatch and still could not
	// be unpacked, which is a gap in the SBOM rather than a file to skip. A stray magic and an implausible
	// header mean "not something we can catalog" and stay quiet, so a new guard added later is silent by
	// default instead of turning into SBOM noise.
	//
	// errUnsupportedUPXMethod is the one case that is a real gap and still stays quiet, so it is a policy
	// call rather than a classification: `upx` emits NRV2B unless --lzma was passed, so reporting it would
	// attach an unknown to most packed binaries in an image, the large majority of which are not Go and
	// would have contributed nothing unpacked either. errUPXDecompress reports because its population is
	// the opposite shape: a file we tried to decode and failed on is rare. Implementing NRV2B is what
	// actually closes this, not reclassifying it.
	errUPXDecompress = errors.New("unable to decompress UPX-compressed Go binary")
)

// upxInfo contains parsed UPX header information
type upxInfo struct {
	version       uint8
	format        uint8
	loaderSize    uint16 // l_lsize - size of the loader stub that separates the extents from the tail
	originalSize  uint32 // p_filesize - original uncompressed file size
	blockSize     uint32 // p_blocksize - size of each compression block
	firstBlockOff int64  // offset to first b_info structure

	// inputLen is the real length of the packed file, validated non-zero by parseUPXInfo. Every bound in
	// this file is expressed against it, so it is carried on the header rather than re-derived: a caller
	// that recomputed it could get zero and silently drop the bounds that depend on it.
	inputLen int64
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

// upxDecompressor returns a reader over one block's decompressed contents, which the caller streams into
// place. Returning a stream rather than filling a caller-owned slice is what keeps a block from being
// resident in full; implementations must produce exactly size bytes.
type upxDecompressor func(compressedData []byte, size int64) (io.Reader, error)

// maxDictionaryFor is the largest LZMA dictionary a block may ask for, given the compressed bytes it
// brought with it. The decoder allocates it up front, before reading a compressed byte, so this is the one
// allocation still sized by something a block declares about itself. Paying for it in sz_cpr, which
// readChainBlock has already checked against the real input length, is what keeps a few dozen header bytes
// from reaching maxUPXOriginalSize.
//
// Under-sizing is safe in the strict direction: the decoder rejects a match whose distance runs past the
// dictionary, so the block fails to decode and the reconstruction is reported partial. It never decodes to
// something wrong.
func maxDictionaryFor(compressedLen int) uint32 {
	allowed := uint64(compressedLen) * maxUPXDictionaryExpansion
	return uint32(min(max(allowed, minUPXDictionary), maxUPXDictionary))
}

// upxDecompressors maps compression methods to their decompressor functions
var upxDecompressors = map[uint8]upxDecompressor{
	upxMethodLZMA:   decompressLZMA,
	upxMethodStored: decompressStored,

	// note: the NRV algorithms are from the UCL library, an open-source implementation based on the NRV (Not Really Vanished) algorithm.
	// TODO: future methods can be added here
	// upxMethodNRV2B: decompressNRV2B,
	// upxMethodNRV2D: decompressNRV2D,
	// upxMethodNRV2E: decompressNRV2E,
}

// blockDecompressor picks the decompressor for a block, or reports false when the block is not something
// we can read. Method 0 is a copy, which is only meaningful when the two sizes agree; treating a mismatch
// as unsupported keeps a stray b_info-shaped run of bytes quiet rather than failing the file over it.
func blockDecompressor(block *blockInfo) (upxDecompressor, bool) {
	if block.method == upxMethodStored && block.compressedSize != block.uncompressedSize {
		return nil, false
	}
	d, ok := upxDecompressors[block.method]
	return d, ok
}

// decompressStored returns the block's bytes as-is, for an extent UPX wrote uncompressed.
func decompressStored(compressedData []byte, size int64) (io.Reader, error) {
	if int64(len(compressedData)) != size {
		return nil, fmt.Errorf("stored block holds %d bytes but declares %d", len(compressedData), size)
	}
	return bytes.NewReader(compressedData), nil
}

// unfilter49 reverses UPX filter 0x49 (CTO), which rewrites x86/x64 CALL (0xE8) and JMP (0xE9) targets
// big-endian with cto8 as a high-byte marker to compress better:
//
//	original:  E8 xx xx xx xx  (CALL rel32, little-endian offset)
//	filtered:  E8 CC yy yy yy  (big-endian, CC = cto8 marker)
//
// data may be a window into a larger block, so base says where it begins (the arithmetic is block-relative)
// and the return is the count of settled leading bytes. When final is false, trailing positions whose
// six-byte lookahead is not yet buffered are left for the next window.
func unfilter49(data []byte, cto8 byte, base uint32, final bool) int {
	cto := uint32(cto8) << 24

	// one past the last position this window can evaluate. A conditional jump needs six bytes and a CALL
	// five, so only the final window (where the shorter form has nothing left to wait for) goes to len-4.
	limit := len(data) - 5
	if final {
		limit = len(data) - 4
	}
	if limit < 0 {
		limit = 0
	}

	for i := 0; i < limit; i++ {
		pos := base + uint32(i)
		opcode := data[i]

		// check for E8 (CALL) or E9 (JMP)
		if opcode == 0xE8 || opcode == 0xE9 {
			// check if first byte after opcode matches cto8 marker
			if data[i+1] == cto8 {
				// read operand as big-endian
				jc := binary.BigEndian.Uint32(data[i+1 : i+5])
				// subtract cto and position to get original relative address, written back little-endian
				binary.LittleEndian.PutUint32(data[i+1:i+5], jc-(pos+1)-cto)
			}
		}

		// check for conditional jumps (0F 80-8F)
		if opcode == 0x0F && i+6 <= len(data) {
			opcode2 := data[i+1]
			if opcode2 >= 0x80 && opcode2 <= 0x8F && data[i+2] == cto8 {
				jc := binary.BigEndian.Uint32(data[i+2 : i+6])
				binary.LittleEndian.PutUint32(data[i+2:i+6], jc-(pos+2)-cto)
			}
		}
	}

	if final {
		return len(data)
	}
	// the bytes from limit on are still reachable by unprocessed positions, so they stay in the window
	return limit
}

// unpackUPX returns the contents the caller should read this binary from, and never nil: with nothing to
// unpack the answer is the input as it was found. No UPX header, a header that did not belong to real UPX
// output, and an unimplemented method (upx emits NRV2B unless --lzma was passed) all stay quiet, since
// reporting them would attach an unknown to every packed non-Go binary in an image.
//
// A non-nil error means the file really is packed and we still could not read it, which is a gap in the
// SBOM; decompressUPX marks exactly those with errUPXDecompress, and a header refused by the size bounds
// carries errUPXSizeRefused. The contents come back alongside the error, still readable, so the caller can
// carry on with the packed bytes and report the gap.
//
// A reconstruction that decoded but came up short carries errUPXPartial, and comes back as the contents
// to read from: it is usually still enough for .go.buildinfo, and the caller reports what was lost.
//
// A cancelled context comes back as ctx.Err() so the caller stops rather than going on to parse the packed
// bytes; it is not a gap in the SBOM and the caller does not report it as one.
//
// A nil buffer means there was nothing to unpack and the caller should read the input as it was found.
// Resolve that with readerFor rather than widening the nil into an io.ReaderAt, which yields a non-nil
// interface holding a nil pointer.
//
// The caller owns the contents and must Close them, which closeUnpacked does for the nil case too.
func unpackUPX(ctx context.Context, r io.ReaderAt) (unpackedContents, error) {
	// the container gate first: this runs over every file in an image and almost none are packed ELF, so
	// nothing above it should cost more than six bytes. ReaderSize seeks to the end and reads the last
	// byte back, which over a squashfs or tar-backed reader is a real seek-and-decompress.
	if !isELF64LE(r) {
		return nil, nil
	}

	size, ok := intFile.ReaderSize(r)
	if !ok {
		// without a real byte count there is nothing to weigh a header claim against, so decline to unpack
		// rather than run the bounds against a zero
		log.Trace("UPX: input size could not be determined, not unpacking")
		return nil, nil
	}

	// the header is parsed before the temp dir is demanded, so a context without one cannot turn every
	// binary the cataloger touches into a reportable failure. Only a file that really is packed needs it.
	info, err := parseUPXInfo(r, size)
	if err != nil {
		if errors.Is(err, errUPXSizeRefused) {
			return nil, err
		}
		log.WithFields("error", err).Trace("not a readable UPX-packed binary")
		return nil, nil
	}

	td := tmpdir.FromContext(ctx)
	if td == nil {
		return nil, fmt.Errorf("%w: no temp dir factory in context", errUPXDecompress)
	}

	out, err := decompressUPX(ctx, td, r, info)
	if errors.Is(err, errUPXPartial) {
		// short, but real and readable: this is still what the caller should read the binary from, and the
		// reason goes back with it so the missing bytes are reported rather than silently dropped
		return out, err
	}
	if err != nil {
		// decompressUPX already released it on every path that returns an error, so this is for the one
		// that does not: errUPXPartial is handled above, and out is nil here
		closeUnpacked(out)
		// cancellation is not a decompression failure and not a gap in the SBOM, but it does mean stop:
		// swallowing it here sent the caller on to parse the packed bytes and build packages after the
		// scan had been called off.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(err, errUPXDecompress) {
			return nil, err
		}
		log.WithFields("error", err).Trace("not a readable UPX-packed binary")
		return nil, nil
	}
	return out, nil
}

// blockSink is where decompression places the blocks it decodes. Writes land at offsets the packed file
// names, Size is the contiguous run rebuilt from offset zero, and FirstGap is where a block that declares
// no home of its own fits. spillbuf.Buffer is what implements it, and naming that type here would say the
// decoder cares whether those bytes are in memory or on disk, which is the one thing it must not care
// about.
type blockSink interface {
	io.WriterAt

	// read back as well as written: the first block carries the ELF program headers that place every
	// block after the second, so a write-only sink would place those by hole-filling alone
	io.ReaderAt

	// Size is the contiguous run rebuilt from offset zero, not the furthest offset written: see upx.go's
	// header and the spillbuf package doc for why the two are not interchangeable.
	Size() int64

	// FirstGap returns the earliest unwritten run of at least size bytes lying within [0, within).
	FirstGap(size, within int64) (int64, bool)
}

// decompressUPX reconstructs the original file from a UPX-compressed ELF binary: it walks the b_info
// chain and decodes each block into the offset it occupied in the original, which blockDestination works
// out from the PT_LOAD segments in the first decoded block. Simply concatenating the blocks produces
// invalid output.
//
// Where those bytes live is spillbuf's problem, not this function's. What matters here is that the buffer
// reports only the contiguous run rebuilt from offset zero: a block's placement offset is attacker
// controlled, and sparse storage hands holes back as zeros, so a length covering them would let a 64 byte
// block parked at p_filesize-64 turn a 300KB input into a 64MB reader.
//
// errUPXImplausibleHeader means the file is not really packed, errUPXPartial a reconstruction that came up
// short but is still worth reading, and only errUPXDecompress a packed file we could not read at all.
func decompressUPX(ctx context.Context, td *tmpdir.TempDir, r io.ReaderAt, info *upxInfo) (unpackedContents, error) {
	out := spillbuf.New(td)

	// errUPXPartial means the chain gave something up but what it rebuilt is worth reading, so it comes
	// back alongside the buffer. Any other error is fatal and the buffer goes with it.
	err := decompressUPXBlocks(ctx, r, info, out)
	if err != nil && !errors.Is(err, errUPXPartial) {
		_ = out.Close()
		return nil, err
	}
	if out.Size() == 0 {
		_ = out.Close()
		// a plausible header with nothing decodable behind it is not a packed binary
		return nil, fmt.Errorf("%w: no decodable blocks", errUPXImplausibleHeader)
	}

	return out, err
}

// loaderSkip is the one-time jump past the loader stub. The extents that rebuild the loadable segments
// are followed by that stub, and behind it UPX packs everything the segments did not cover: the alignment
// padding between them and the non-loadable tail (section headers, the section name table, symbols, debug
// data). Picking the chain back up past the loader is the difference between a file we can only read build
// info out of and one we can also read symbols out of. Anything else sitting there fails validation and
// ends the chain.
type loaderSkip struct {
	size uint16
	done bool
}

// past reports the offset the chain resumes at, and false once the jump has been spent or there is no
// stub to jump over.
func (l *loaderSkip) past(offset int64) (int64, bool) {
	if l.done || l.size == 0 {
		return offset, false
	}
	l.done = true
	return offset + int64(l.size), true
}

// decompressUPXBlocks walks the b_info chain, decoding each block into its place in the reconstructed
// file. A chain that simply ends, describes a layout it does not hold, or holds a block that will not
// decode yields the blocks placed so far, since those are often enough to recover .go.buildinfo; the
// result says so through partial. Only the first block failing, or a cancelled scan, discards everything,
// since then there is nothing here to read.
//
// out is read back and questioned as well as written: the first block carries the ELF program headers that
// say where the rest belong, so a write-only sink would place every later block by hole-filling and hand
// back a plausible but wrongly shaped file. Size is the contiguous run rebuilt from offset zero, which is
// what the reconstruction can deliver, and FirstGap is where a block fits in the earliest hole left behind.
func decompressUPXBlocks(ctx context.Context, r io.ReaderAt, info *upxInfo, out blockSink) error {
	// UPX packs the original file as a series of blocks that together reconstruct p_filesize. Track the
	// unclaimed remainder so the block headers cannot drive more decompression than the file itself
	// declares: without this, every block may individually claim the whole original size, and the total
	// work becomes (block count x original size). This is the bound that does the real work here.
	remaining := info.originalSize

	currentOffset := info.firstBlockOff
	outputOffset := uint64(0)
	blockNum := 0
	loader := loaderSkip{size: info.loaderSize}
	var ptLoadOffsets []uint64

	// why the chain stopped, when it stopped short of a clean end marker. Set once at the break that
	// caused it; finalExtent turns it into the reconstruction's partial reason.
	var stopped error

	for blockNum < maxUPXBlocks {
		// a hostile chain can drive maxUPXBlocks decodes of maxUPXOriginalSize between them, so the loop
		// has to be interruptible: this is the only long-running work in the cataloger that is sized by
		// the file it is reading.
		// deliberately not wrapped in errUPXDecompress: a cancelled scan is not a gap in the SBOM, so it
		// stays on the quiet side of the reportability split like every other non-decompress failure.
		if err := ctx.Err(); err != nil {
			return err
		}

		block, decompressor, err := readChainBlock(r, currentOffset, blockNum, info.inputLen)
		if err != nil {
			return err
		}
		if block == nil {
			if next, ok := loader.past(currentOffset); ok {
				currentOffset = next
				continue
			}
			break
		}

		// blockNum is 0-based here and 1-based past the increment below, so both fail-hard gates on it
		// mean "the first block". Hoisted so they read as the same predicate.
		first := blockNum == 0

		if block.uncompressedSize > remaining {
			fatal, reason := classifyOverrun(first, blockNum, block.uncompressedSize, remaining, info.originalSize)
			if fatal != nil {
				return fatal
			}
			stopped = reason
			break
		}
		remaining -= block.uncompressedSize
		blockNum++

		destOffset, ok := blockDestination(blockNum, block.uncompressedSize, outputOffset, ptLoadOffsets, out, uint64(info.originalSize))
		if !ok {
			// the file does not describe the layout it claims. Keep the blocks placed so far, but stop:
			// outputOffset derives from destOffset, so continuing would carry the bad offset forward.
			stopped = fmt.Errorf("%w: block %d of %d bytes does not fit the declared %d byte layout",
				errUPXPartial, blockNum, block.uncompressedSize, info.originalSize)
			break
		}

		if err := decompressBlock(ctx, r, block, decompressor, out, destOffset); err != nil {
			fatal, reason := classifyDecodeFailure(ctx, err, first, blockNum)
			if fatal != nil {
				return fatal
			}
			stopped = reason
			break
		}
		blockEnd := destOffset + uint64(block.uncompressedSize)

		// the first block carries the original ELF headers, which place every block after the second
		if blockNum == 1 {
			ptLoadOffsets = readPTLoadOffsets(out, destOffset, block.uncompressedSize)
		}

		outputOffset = blockEnd
		currentOffset = block.dataOffset + int64(block.compressedSize)
	}

	return finalExtent(uint64(out.Size()), blockNum, uint64(info.originalSize), stopped)
}

// classifyOverrun decides what a block claiming more output than the running remainder allows means.
// Exactly one of the two results is non-nil, the same contract as classifyDecodeFailure.
//
// The blocks together reconstruct p_filesize, so that remainder bounds the total output. It is deliberately
// the only size check on a block: comparing sz_unc against p_blocksize as well adds nothing (remaining is
// already <= p_filesize) and real output sits at exactly p_blocksize, so that check would run with no
// headroom against a value the format does not guarantee.
//
// Past the first block this ends the chain rather than failing the file, the same way readChainBlock treats
// a method it cannot read: the bytes behind the last block are loader stub, and a run of machine code that
// happens to parse as a b_info is not a claim about the file. The bound holds either way, since the
// overrunning block is never placed.
func classifyOverrun(first bool, blockNum int, size, remaining uint32, total uint32) (fatal, reason error) {
	if first {
		return fmt.Errorf("%w: %w: block %d claims %d with %d left of %d", errUPXDecompress,
			errUPXOutputExceeded, blockNum+1, size, remaining, total), nil
	}
	return nil, fmt.Errorf("%w: block %d claims %d bytes with %d left of %d", errUPXPartial,
		blockNum+1, size, remaining, total)
}

// classifyDecodeFailure decides what a block that would not decode means. Exactly one of the two results
// is non-nil: a fatal error ends the file, a reason ends the chain and keeps what came before it.
//
// A cancelled copy arrives here as a decode failure, so ctx is checked first. Classifying it as one would
// put it on the quiet arm for block 1 and turn it into errUPXPartial after that: an aborted scan is not a
// gap in the SBOM, it is a reason to stop.
//
// Past the first block a failure ends the chain rather than failing the file, for the same reason an
// overrunning block does: readChainBlock accepts any b_info-shaped run of bytes with a method it knows, so
// the loader stub behind the last real block can parse as one and then fail to decode. Discarding a good
// reconstruction over garbage past the end of it is the worse answer. The bound still holds, since only real
// decoder output was ever written, but a block that failed mid-stream leaves its decoded prefix behind, so
// the reconstruction can end inside that block. That is what errUPXPartial reports.
func classifyDecodeFailure(ctx context.Context, err error, first bool, blockNum int) (fatal, reason error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr, nil
	}
	if first {
		return fmt.Errorf("%w: %w", errUPXDecompress, err), nil
	}
	return nil, fmt.Errorf("%w: block %d did not decode: %w", errUPXPartial, blockNum, err)
}

// finalExtent reports why the reconstruction is short of what the header declared, or nil when it is not.
// None of these is a failure: the blocks placed so far may still carry .go.buildinfo. They are reported
// rather than logged because the bytes past the covered prefix are gone, and a binary that quietly
// contributes nothing because its section-name table sat past a gap is the failure this avoids.
func finalExtent(covered uint64, blockNum int, total uint64, stopped error) error {
	// a chain that rebuilt everything p_filesize claimed lost nothing, whatever it tripped over next. The
	// bytes behind the last real block are loader stub, and readChainBlock accepts any run of those that
	// parses as a b_info with a method it knows, so a clean unpack routinely ends by reading one and
	// finding it overruns a remaining of zero. Reporting that as a gap puts an unknown on a binary the
	// cataloger read completely.
	if covered >= total {
		return nil
	}

	switch {
	case stopped != nil:
		// the chain gave up mid-walk, which is more specific than anything the extents show
		return stopped
	case blockNum == maxUPXBlocks:
		return fmt.Errorf("%w: the block chain hit the %d block cap", errUPXPartial, maxUPXBlocks)
	}

	// the chain ran out before rebuilding what the header declared, and nothing above says why: every
	// readChainBlock exit that ends the chain quietly lands here, once the arms above have had their say:
	// an unreadable b_info, the end marker, a zero sz_cpr, compressed data past the end of the input, and
	// a method we cannot read past the first block (on the first block that fails the file). Real UPX output
	// rebuilds p_filesize exactly, so the bytes past the covered prefix are gone the same way they are in
	// every case above, and truncating to the prefix drops whatever sat behind it. Left unreported this is
	// the one shape where a short reconstruction can cost the binary its section headers and contribute
	// neither packages nor an unknown.
	return fmt.Errorf("%w: the chain ended after %d of the declared %d bytes", errUPXPartial, covered, total)
}

// readChainBlock reads the b_info at offset and pairs it with the decompressor for its method. A nil block
// alongside a nil error means the chain ends here: an unreadable header, the end marker, a block whose
// compressed data is not in the file, or a method we cannot read, which is what the loader bytes behind
// the last block look like. An unimplemented method on the very first block is the one case that fails the
// file, since then there is nothing here to read.
func readChainBlock(r io.ReaderAt, offset int64, blockNum int, inputLen int64) (*blockInfo, upxDecompressor, error) {
	block, err := readBlockInfo(r, offset)
	if err != nil {
		// a real UPX file runs out of b_info structures before it runs out of blocks
		log.WithFields("block", blockNum+1, "offset", offset, "error", err).
			Trace("UPX block info unreadable, using partial output")
		return nil, nil, nil
	}
	if block.uncompressedSize == 0 {
		return nil, nil, nil // end marker
	}

	// sz_cpr sizes a read buffer directly, so on its own a few dozen header bytes could name a length the
	// following ReadAt could only ever fail. A block whose data is not in the file, or which holds no
	// compressed bytes at all, ends the chain: neither is something a decoder can be handed.
	if block.compressedSize == 0 {
		log.WithFields("block", blockNum+1, "offset", offset).
			Trace("UPX block holds no compressed data, using partial output")
		return nil, nil, nil
	}
	if block.dataOffset > inputLen || int64(block.compressedSize) > inputLen-block.dataOffset {
		log.WithFields("block", blockNum+1, "compressedSize", block.compressedSize, "inputSize", inputLen).
			Trace("UPX block claims compressed data past the end of the input, using partial output")
		return nil, nil, nil
	}

	decompressor, ok := blockDecompressor(block)
	if !ok {
		if blockNum == 0 {
			return nil, nil, fmt.Errorf("%w: method %d", errUnsupportedUPXMethod, block.method)
		}
		return nil, nil, nil
	}
	return block, decompressor, nil
}

// blockDestination decides where a block lands in the reconstructed file, reporting false when the file
// does not describe a layout it fits in. The first two blocks (the original ELF headers and the extent
// behind them) run sequentially from the start of the file, the ones after that go to the PT_LOAD offsets
// parsed out of the first, and whatever is left fills the gaps those leave behind, in file order.
//
// Block 3 indexes ptLoadOffsets[1], not [0]: block 2 is the first loadable extent and was already placed
// sequentially, which is where the first PT_LOAD lives. The offset is not an off-by-one.
func blockDestination(blockNum int, size uint32, sequential uint64, ptLoadOffsets []uint64, out blockSink, total uint64) (uint64, bool) {
	switch {
	case blockNum > 2 && blockNum-2 < len(ptLoadOffsets):
		dest := ptLoadOffsets[blockNum-2]
		return dest, blockFits(total, dest, size)
	case blockNum > 2:
		at, ok := out.FirstGap(int64(size), int64(total))
		return uint64(at), ok
	default:
		return sequential, blockFits(total, sequential, size)
	}
}

// blockFits reports whether a block of the given size lands entirely within a total byte file when placed
// at destOffset. destOffset comes from an ELF p_offset in the file, so the check is written as a
// subtraction rather than as destOffset+size, which could wrap.
//
// The wrap is not reachable today: it needs destOffset above 2^64-2^32, and every such value is negative
// once decompressBlock converts it to an int64 for WriteAt, which fails there instead. Kept in this form
// anyway, since the reason it is unreachable lives in another function.
func blockFits(total, destOffset uint64, size uint32) bool {
	return destOffset <= total && uint64(size) <= total-destOffset
}

// decompressBlock reads one block's compressed data and streams it into the output at destOffset,
// reversing the CTO filter on the way through if the block declares one. The decompressed block is never
// held in full: it moves through a fixed window, so the copy costs the same whatever sz_unc says.
//
// That bounds the copy, not the decoder. lzma.NewReader allocates a dictionary of min(dictSize, sz_unc)
// before it reads a compressed byte, so sz_unc still buys heap; what keeps that payable is the input-size
// ratio on p_filesize, which the running remainder holds every block underneath.
func decompressBlock(ctx context.Context, r io.ReaderAt, block *blockInfo, decompressor upxDecompressor, out io.WriterAt, destOffset uint64) error {
	// readChainBlock has already bounded sz_cpr by the real input length, but on a 32-bit GOARCH an input
	// past 2GB leaves a length make() panics on, and that panic is outside the recover in getBuildInfo.
	if uint64(block.compressedSize) > math.MaxInt {
		return fmt.Errorf("compressed block of %d bytes is larger than this platform can address", block.compressedSize)
	}
	compressedData := make([]byte, block.compressedSize)
	if _, err := r.ReadAt(compressedData, block.dataOffset); err != nil {
		return fmt.Errorf("failed to read compressed data: %w", err)
	}

	size := int64(block.uncompressedSize)
	src, err := decompressor(compressedData, size)
	if err != nil {
		return fmt.Errorf("failed to decompress block: %w", err)
	}

	src = ctxReader{ctx: ctx, r: src}

	dst := io.NewOffsetWriter(out, int64(destOffset))
	if block.filterID == upxFilterCTO {
		return copyUnfiltered(dst, src, size, block.filterCTO)
	}
	if block.filterID != 0 {
		log.WithFields("filter", block.filterID).Trace("UPX filter not implemented, copying block unfiltered")
	}
	if _, err := io.CopyN(dst, src, size); err != nil {
		return fmt.Errorf("failed to decompress block: %w", err)
	}
	return nil
}

// ctxReader fails a read once ctx is done. The block copy below moves up to a whole sz_unc through a
// fixed window, so without this a cancelled scan still finished the block it was on: one check per block
// meant one check per up-to-maxUPXOriginalSize of work, and a single-block chain got exactly one, before
// any work had started. Wrapping the decoder output covers io.CopyN and copyUnfiltered together.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// copyUnfiltered copies size bytes from src to dst, reversing the CTO filter as it passes. The filter is
// a forward scan, so it runs over a sliding window: each round processes only the positions whose
// lookahead is buffered, flushes the settled bytes and carries the tail into the next round.
func copyUnfiltered(dst io.Writer, src io.Reader, size int64, cto8 byte) error {
	buf := make([]byte, min(size, upxFilterWindow))
	var base int64 // block-relative position of buf[0]
	var filled int

	for {
		// int64 throughout: size is a uint32 widened, and on a 32-bit GOARCH an int conversion of a value
		// past 2^31 goes negative, which stalls the loop instead of erroring. min() with an int64 len keeps
		// the result in range for the slice bounds below.
		if want := int(min(int64(len(buf)-filled), size-base-int64(filled))); want > 0 {
			n, err := io.ReadFull(src, buf[filled:filled+want])
			filled += n
			if err != nil {
				return fmt.Errorf("failed to decompress block: %w", err)
			}
		}

		final := base+int64(filled) >= size
		settled := unfilter49(buf[:filled], cto8, uint32(base), final)
		if _, err := dst.Write(buf[:settled]); err != nil {
			return fmt.Errorf("failed to write decompressed block: %w", err)
		}
		if final {
			return nil
		}
		// a non-final window is always a full buf, and upxFilterWindow leaves unfilter49 room to settle at
		// least one byte, so this cannot fire. Checked because the alternative to erroring is a loop that
		// never terminates, and the invariant that rules it out is not local to this function.
		if settled == 0 {
			return fmt.Errorf("failed to decompress block: the CTO filter made no progress at offset %d", base)
		}

		copy(buf, buf[settled:filled])
		base += int64(settled)
		filled -= settled
	}
}

// readPTLoadOffsets reads back the head of the first placed block to recover the PT_LOAD offsets that
// position the later blocks. Only the head is read: the program headers of a real ELF64 sit right behind
// the 64 byte file header, and the block itself may be far too large to bring back into memory.
//
// note: ELF64 little-endian only. parseELFPTLoadOffsets returns nil for anything else, which does not stop
// the reconstruction; the later blocks fall back to hole-filling in file order.
func readPTLoadOffsets(r io.ReaderAt, destOffset uint64, size uint32) []uint64 {
	head := make([]byte, min(uint64(size), uint64(upxELFHeaderWindow)))
	n, err := r.ReadAt(head, int64(destOffset))
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithFields("offset", destOffset, "error", err).Trace("unable to read back the UPX ELF header block")
		return nil
	}
	// only what was actually read: the tail of head is zeros on a short read, and a p_offset of zero
	// parsed out of it would place a later block over the ELF header.
	return parseELFPTLoadOffsets(head[:n])
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

		// the bounds test below is written as `hdrLen-phStart` rather than `phStart+phentsize > hdrLen`
		// so that a large phoff cannot overflow the sum past the buffer end. The `break` is load-bearing
		// for that argument too: it guarantees phoff <= hdrLen before any i >= 1 is reached, which is what
		// keeps phStart itself from wrapping; a `continue` here would let phoff near 2^64 wrap into a
		// small in-range phStart and read a bogus p_offset.
		//
		// Not covered by a test, and worth knowing why before trying to write one: reaching the wrap needs
		// phoff >= 2^64-phentsize, so the wrapped phStart always lands inside the first 56 bytes of the
		// file, which is the ELF ident and header. Whether it then reads as PT_LOAD depends on header
		// fields the fixture builder here does not set, so a test would have to hand-roll the header to
		// place a 1 at the wrapped offset. The arithmetic is the argument.
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

// parseUPXInfo locates and parses the UPX header information. inputLen is the size of the file behind r,
// which every bound here is expressed against; a file whose size cannot be determined cannot be unpacked,
// since there is then nothing to weigh a claim against.
func parseUPXInfo(r io.ReaderAt, inputLen int64) (*upxInfo, error) {
	// unpackUPX applies this gate too, and cheaply, so on the production path it runs twice. Kept here
	// because this function owns the invariant every read below it depends on: the l_info/p_info offsets,
	// the block placement and readPTLoadOffsets are all ELF64 little-endian at fixed offsets, and the
	// tests call it directly.
	if !isELF64LE(r) {
		return nil, errNotUPX
	}

	buf := make([]byte, upxMagicScanWindow)
	n, err := r.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	magicIdx := bytes.Index(buf[:n], upxMagic)
	if magicIdx == -1 {
		return nil, errNotUPX
	}

	// see the format tables at the top of this file for the l_info/p_info/b_info layouts

	// the reads below reach magic+20 (the end of p_info); b_info comes from ReadAt later. Wrapped as an
	// implausible header rather than its own error so the caller keeps treating it as "not really UPX".
	const lInfoAndPInfoSize = 20
	if magicIdx+lInfoAndPInfoSize > n {
		return nil, fmt.Errorf("%w: header runs past the end of the scan window", errUPXImplausibleHeader)
	}

	lInfoBase := buf[magicIdx:]
	pInfoBase := buf[magicIdx+8:] // p_info starts 8 bytes after magic

	info := &upxInfo{
		loaderSize:    binary.LittleEndian.Uint16(lInfoBase[4:6]),
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
	// p_filesize is the budget every block is drawn against, so it bounds the bytes written to the
	// reconstruction. Nothing allocates against it, which is why this is a ratio and not a ceiling: a
	// large binary is unpacked at whatever size it really is, and only a claim the input cannot pay for
	// is refused.
	if info.originalSize == 0 {
		return nil, fmt.Errorf("%w: p_filesize is zero", errUPXImplausibleHeader)
	}
	if inputLen <= 0 {
		return nil, fmt.Errorf("%w: the size of the input could not be determined", errUPXImplausibleHeader)
	}
	if limit := uint64(inputLen) * maxUPXExpansion; uint64(info.originalSize) > limit {
		return nil, fmt.Errorf("%w: p_filesize %d exceeds the %d byte limit for a %d byte input",
			errUPXSizeRefused, info.originalSize, limit, inputLen)
	}
	if uint64(info.originalSize) > maxUPXOriginalSize {
		return nil, fmt.Errorf("%w: p_filesize %d is over the %d byte ceiling",
			errUPXSizeRefused, info.originalSize, uint64(maxUPXOriginalSize))
	}
	info.inputLen = inputLen

	return info, nil
}

// isELF64LE reports whether r opens with an ELF64 little-endian ident. This reconstructs that container
// and only that: parseELFPTLoadOffsets reads the program headers at fixed ELF64 little-endian offsets, and
// nothing else here understands another layout. UPX packs PE and Mach-O with the same l_info/p_info
// layout, so without this gate a packed Windows binary parses as a plausible header, demands a temp dir,
// places its blocks by ELF rules that do not apply, and lands as an unknown on a file we were never going
// to catalog.
//
// A packed ELF32 or big-endian ELF is refused here too, and quietly, which is a known inconsistency with
// the reporting policy in reportableGap: those are packed Go binaries we could have cataloged, so by that
// policy they are a gap worth reporting rather than a container to skip. Left quiet deliberately. The
// honest fix is to reconstruct them, which is class- and order-aware program header parsing rather than a
// reclassification, and until then an unknown on every packed 32-bit binary in an image buys nothing a
// caller can act on. Not a regression: the pre-branch parser also bailed on anything but ELF64 LE, it just
// did so after demanding a temp dir and walking the chain.
func isELF64LE(r io.ReaderAt) bool {
	var ident [6]byte
	if n, err := r.ReadAt(ident[:], 0); n < len(ident) || (err != nil && !errors.Is(err, io.EOF)) {
		return false
	}
	return bytes.Equal(ident[:4], []byte{0x7f, 'E', 'L', 'F'}) && ident[4] == 2 && ident[5] == 1
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

	// sz_cpr is taken whole. Some UPX formats store flags in its high 8 bits, but the ELF format this code
	// handles (the only one the container gate accepts) keeps filter data in b_ftid/b_cto8, so masking here
	// would not decode a flag: it would silently turn a length above 16MB into a smaller plausible one and
	// read that many bytes of a longer stream. readChainBlock bounds the value against the input instead,
	// which ends the chain on a length the file cannot hold rather than truncating it.
	block := &blockInfo{
		uncompressedSize: szUnc,
		compressedSize:   szCpr,
		method:           buf[8],
		filterID:         buf[9],
		filterCTO:        buf[10],
		dataOffset:       offset + 12, // data starts right after b_info
	}

	return block, nil
}

// decompressLZMA returns a reader over LZMA-compressed data as used by UPX.
// UPX uses a 2-byte custom header format, not the standard 13-byte LZMA format.
//
// UPX 2-byte header encoding:
//   - Byte 0: (t << 3) | pb, where t = lc + lp
//   - Byte 1: (lp << 4) | lc
//   - Byte 2+: raw LZMA stream (starts with 0x00 for range decoder init)
//
// Standard LZMA props encoding: props = lc + lp*9 + pb*9*5
func decompressLZMA(compressedData []byte, size int64) (io.Reader, error) {
	if len(compressedData) < 3 {
		return nil, errors.New("compressed data too short")
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
		return nil, fmt.Errorf("%w: lc=%d lp=%d pb=%d", errUPXInvalidLZMAParams, lc, lp, pb)
	}
	if uint16(lc)+uint16(lp) > maxUPXLZMALiteralBits {
		return nil, fmt.Errorf("%w: lc+lp=%d exceeds %d", errUPXInvalidLZMAParams, lc+lp, maxUPXLZMALiteralBits)
	}

	// convert to standard LZMA properties byte
	props := lc + lp*9 + pb*9*5

	// raw LZMA stream starts at byte 2 (includes 0x00 init byte)
	lzmaStream := compressedData[2:]

	uncompressedSize := uint32(size)

	// the dictionary only has to cover the uncompressed size and sit inside the library's own range; it is
	// not required to be a power of two. The library allocates min(dictSize, header size) up front, before
	// reading a compressed byte, so this is the file's one remaining heap knob and maxDictionaryFor is
	// what bounds it.
	//
	// note: if you're seeing that testing small binaries works and large ones don't,
	// it may be that the dictionary size was not considered properly in this code.
	dictSize := min(max(uncompressedSize, minUPXDictionary), maxDictionaryFor(len(compressedData)))

	// construct standard 13-byte LZMA header
	header := make([]byte, 13)
	header[0] = props
	binary.LittleEndian.PutUint32(header[1:5], dictSize)
	binary.LittleEndian.PutUint64(header[5:13], uint64(uncompressedSize))

	// MultiReader rather than concatenating, so the compressed block is not copied a second time
	reader, err := lzma.NewReader(io.MultiReader(bytes.NewReader(header), bytes.NewReader(lzmaStream)))
	if err != nil {
		return nil, fmt.Errorf("failed to create LZMA reader: %w", err)
	}
	return reader, nil
}

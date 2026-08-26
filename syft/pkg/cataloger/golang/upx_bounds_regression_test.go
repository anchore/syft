package golang

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/elfutil"
	"github.com/anchore/syft/syft/internal/unionreader"
)

// the reconstruction's storage, its Close semantics and the contiguous-prefix rule it reports as Size all
// belong to internal/spillbuf now, and are tested there. What is left in this file is what the golang
// cataloger does with them.

// sparseFixture is a UPX file whose first block carries an ELF header declaring a second PT_LOAD segment
// at farOffset, so a tiny third block is placed there. declaredShstrtab, when non-zero, makes that ELF
// header also declare a section name table of that size sitting inside the gap, which is what turns the
// reader's length into an allocation for anything that parses it.
func sparseFixture(t *testing.T, declared uint32, farOffset, declaredShstrtab uint64, pad int) []byte {
	t.Helper()

	phdrs := make([]byte, 112)
	binary.LittleEndian.PutUint32(phdrs[0:4], 1)  // phdr[0] PT_LOAD
	binary.LittleEndian.PutUint64(phdrs[8:16], 0) // p_offset 0
	binary.LittleEndian.PutUint32(phdrs[56:60], 1)
	binary.LittleEndian.PutUint64(phdrs[64:72], farOffset) // phdr[1] p_offset, out at the declared end

	hdr := make([]byte, 64)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F'})
	hdr[4], hdr[5], hdr[6] = 2, 1, 1 // ELFCLASS64, little endian, EV_CURRENT
	binary.LittleEndian.PutUint16(hdr[0x10:0x12], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(hdr[0x12:0x14], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(hdr[0x14:0x18], 1)
	binary.LittleEndian.PutUint64(hdr[0x20:0x28], 64) // e_phoff
	binary.LittleEndian.PutUint16(hdr[0x36:0x38], 56) // e_phentsize
	binary.LittleEndian.PutUint16(hdr[0x38:0x3a], 2)  // e_phnum

	block1 := append(hdr, phdrs...)
	if declaredShstrtab > 0 {
		sh := make([]byte, 128) // two section headers; index 1 is the name table
		binary.LittleEndian.PutUint32(sh[64+4:64+8], uint32(elf.SHT_STRTAB))
		binary.LittleEndian.PutUint64(sh[64+24:64+32], farOffset/2) // sh_offset, inside the gap
		binary.LittleEndian.PutUint64(sh[64+32:64+40], declaredShstrtab)
		binary.LittleEndian.PutUint64(block1[0x28:0x30], 64+112) // e_shoff
		binary.LittleEndian.PutUint16(block1[0x3a:0x3c], 64)     // e_shentsize
		binary.LittleEndian.PutUint16(block1[0x3c:0x3e], 2)      // e_shnum
		binary.LittleEndian.PutUint16(block1[0x3e:0x40], 1)      // e_shstrndx
		block1 = append(block1, sh...)
	}

	data := buildUPXHeader(declared, 4096)
	data = append(data, blockFor(t, block1)...)
	data = append(data, blockFor(t, bytes.Repeat([]byte("B"), 32))...) // sequential
	data = append(data, blockFor(t, bytes.Repeat([]byte("C"), 64))...) // -> ptLoadOffsets[1]
	data = append(data, make([]byte, 12)...)                           // end marker
	return padTo(data, pad)
}

// TestDecompressUPX_ReaderLengthIsWhatWasRebuilt covers the amplification that survives moving the
// reconstruction from the heap to a temp file.
//
// A block's destination comes from a PT_LOAD p_offset in the first block, bounded only by p_filesize, so a
// 64 byte block parked at p_filesize-64 must not make the reconstruction report the full declared size
// while holding only a few hundred real bytes. A sparse file hands its holes back as zeros it never stored,
// so every parser downstream that sizes against "what this reader will deliver" -- which is the whole
// argument for writing to disk rather than the heap -- would otherwise allocate against a number the input
// never paid for.
func TestDecompressUPX_ReaderLengthIsWhatWasRebuilt(t *testing.T) {
	const declared = 64 << 20
	const input = 300_000

	data := sparseFixture(t, declared, declared-64, 0, input)

	out, err := unpack(t, data)
	// the hole is exactly what makes this partial: the blocks past it are given up, and that is reported
	// rather than logged, since a caller reading this reconstruction is missing bytes the header declared
	require.ErrorIs(t, err, errUPXPartial)
	require.NotNil(t, out, "a short reconstruction is still the contents to read from")

	// the ELF header block plus the two small blocks, and nothing for the hole
	assert.Less(t, out.Size(), int64(4096),
		"the reader must be sized by the bytes actually rebuilt, not by where a block was parked")

	_, err = out.ReadAt(make([]byte, 512), int64(declared)/2)
	assert.ErrorIs(t, err, io.EOF, "the hole must not read back as free zeros")
}

func TestDecompressUPX_SparsePlacementIsNotAnAllocationKnob(t *testing.T) {
	// the same fixture, with the reconstructed ELF also declaring a 60MB section name table sitting in the
	// hole. This is the end of the exploit chain: debug/elf grows its read as the reads succeed, and
	// against a hole they all succeed.
	const declared = 64 << 20
	const input = 300_000

	data := sparseFixture(t, declared, declared-64, 60<<20, input)

	out, err := unpack(t, data)
	require.ErrorIs(t, err, errUPXPartial)
	require.NotNil(t, out)

	allocated := measureAlloc(t, func() {
		_, _ = getBuildInfo(out)
	})

	// debug/elf's own first chunk is ~10MB regardless of what a file declares, so the bound to assert is
	// that the declared 60MB is not reachable, not that this is free
	assert.Less(t, allocated, uint64(16*intFile.MB),
		"a 300KB input must not drive tens of MB of allocation through the reconstruction")
}

func TestReadPTLoadOffsets_ShortReadIsNotTrusted(t *testing.T) {
	// on a short read the tail of the buffer is zeros the file never provided, and a p_offset of zero
	// parsed out of it would place a later block over the ELF header.
	phdrs := make([]byte, 112)
	binary.LittleEndian.PutUint32(phdrs[0:4], 1)
	binary.LittleEndian.PutUint64(phdrs[8:16], 0x1000)
	binary.LittleEndian.PutUint32(phdrs[56:60], 1)
	binary.LittleEndian.PutUint64(phdrs[64:72], 0x2000)
	full := buildELF64(64, 56, 2, phdrs)

	assert.Equal(t, []uint64{0x1000, 0x2000}, readPTLoadOffsets(bytes.NewReader(full), 0, uint32(len(full))),
		"the whole header is readable, so both segments come back")

	// the same header with the second program header cut off. The block claims it is there; the file is
	// not that long.
	truncated := full[:64+56+8]
	got := readPTLoadOffsets(bytes.NewReader(truncated), 0, uint32(len(full)))
	assert.Equal(t, []uint64{0x1000}, got,
		"only the segment actually present may be trusted; a zero read out of the gap is not an offset")
}

func TestDecompressUPX_StoredBlockIsPlaced(t *testing.T) {
	// method 0 is an extent UPX could not compress and wrote verbatim, and real output carries a few of
	// them: the alignment padding between PT_LOAD segments is only a handful of bytes. Nothing covered
	// this path outside the Docker-backed fixture.
	payload := bytes.Repeat([]byte("S"), 48)
	stored := make([]byte, 12)
	binary.LittleEndian.PutUint32(stored[0:4], uint32(len(payload))) // sz_unc
	binary.LittleEndian.PutUint32(stored[4:8], uint32(len(payload))) // sz_cpr, equal for a stored block
	stored[8] = upxMethodStored

	data := buildUPXHeader(4096, 4096)
	data = append(data, stored...)
	data = append(data, payload...)
	data = append(data, make([]byte, 12)...)
	data = padTo(data, 512)

	out, err := unpack(t, data)
	// the fixture declares 4096 and delivers one 48 byte extent, so the chain is short by construction and
	// the partial goes with it. Real output rebuilds p_filesize exactly; what is under test is placement.
	require.ErrorIs(t, err, errUPXPartial)
	assert.Equal(t, payload, readAll(t, out), "a stored block is copied through as-is")
}

func TestDecompressUPX_StoredBlockWithMismatchedSizesIsQuiet(t *testing.T) {
	// a copy is only meaningful when the two sizes agree. A mismatch is how a stray b_info-shaped run of
	// bytes looks, so it ends the chain rather than failing the file.
	stored := make([]byte, 12)
	binary.LittleEndian.PutUint32(stored[0:4], 64) // sz_unc
	binary.LittleEndian.PutUint32(stored[4:8], 32) // sz_cpr, disagrees
	stored[8] = upxMethodStored

	data := padTo(append(buildUPXHeader(4096, 4096), stored...), 512)

	_, err := unpack(t, data)
	require.Error(t, err)
	// a stored block whose sizes disagree is not a block we can read, which on the first block is the
	// unsupported-method refusal. Either way it must stay clear of errUPXDecompress.
	assert.ErrorIs(t, err, errUnsupportedUPXMethod, "a copy whose sizes disagree is not a copy")
	assert.NotErrorIs(t, err, errUPXDecompress, "not a packed binary, so it stays quiet")
}

// TestScanReader_ReportingIsNarrow pins which gaps this cataloger claims. It runs against every
// executable in an image, so reporting each file debug/buildinfo cannot parse would attach an unknown to
// most files in a typical one. Only a bound syft itself chose to enforce, and a packed file it could not
// unpack, are real gaps.
func TestScanReader_ReportingIsNarrow(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		report bool
	}{
		{
			name: "a corrupt ELF is not this cataloger's gap",
			data: append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1}, bytes.Repeat([]byte{0xAB}, 512)...),
		},
		{
			name: "neither is a file that is not an executable at all",
			data: bytes.Repeat([]byte("not a binary"), 64),
		},
		{
			name: "nor a truncated PE",
			data: append([]byte("MZ\x90\x00"), bytes.Repeat([]byte{0}, 512)...),
		},
		{
			name: "a section name table syft declined to expand is",
			data: elfDeclaringNameTable(t, 256<<20),
			// this is elfutil.ErrDeclaredSizeExceeded: syft chose not to expand it, so the packages behind
			// it really are missing from the SBOM because of a decision made here
			report: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loc := file.NewLocation("subject")
			_, err := scanReader(context.Background(), loc, bytes.NewReader(tt.data), false)

			if !tt.report {
				assert.NoError(t, err, "this cataloger sees every executable in an image; it must stay quiet here")
				return
			}
			require.Error(t, err)
			var coordErr *unknown.CoordinateError
			require.ErrorAs(t, err, &coordErr, "a reported gap has to carry the location it belongs to")
			assert.Equal(t, loc.Coordinates, coordErr.Coordinates)
			assert.ErrorIs(t, coordErr.Reason, elfutil.ErrDeclaredSizeExceeded,
				"the reported gap has to carry the sentinel the split keys on, not just a message")
		})
	}
}

func TestScanReader_RefusedExpansionIsReportedAsSuch(t *testing.T) {
	// the sentinel is what lets the narrow reporting above tell "syft declined to expand this" apart from
	// "this file is broken", so the two must not collapse into one string match
	_, err := readBuildInfo(bytes.NewReader(elfDeclaringNameTable(t, 256<<20)))
	require.Error(t, err)
	assert.ErrorIs(t, err, elfutil.ErrDeclaredSizeExceeded)
}

// TestReadContentsAndBuildInfo_FakeUPXHeaderCannotHideAGoBinary covers the evasion vector the unpacking
// opened up. The "UPX!" magic is found by an unanchored substring scan over the first 8KB and every field
// behind it is attacker-controlled, so an ordinary Go binary can be made to produce a plausible header and
// a reconstruction of nothing. Reading from that reconstruction unconditionally means the binary reports
// no packages at all, which turns a false positive into a way to hide a dependency list.
// goELF64Fixture returns a real, unpacked Go binary that clears the ELF64 little-endian container gate in
// parseUPXInfo. hello-linux-arm is ELFCLASS32 and is rejected before the UPX magic scan runs, so a test
// that splices a header into it exercises nothing.
func goELF64Fixture(t *testing.T) []byte {
	t.Helper()
	runMakeTarget(t, "archs")
	original, err := os.ReadFile(filepath.Join("testdata", "archs", "binaries", "hello-linux-ppc64le"))
	require.NoError(t, err)
	require.Equal(t, byte(2), original[4], "the container gate only accepts ELF64")
	require.Equal(t, byte(1), original[5], "the container gate only accepts little-endian")
	return original
}

// spliceFakeUPXHeader writes a plausible UPX header plus one decodable block into padding inside the
// magic scan window, leaving the ELF itself intact. The offset is found rather than hardcoded: it has to
// sit past the section header table (writing over that corrupts the binary and the test then proves
// nothing) and inside upxMagicScanWindow (past it the magic is never seen).
func spliceFakeUPXHeader(t *testing.T, original []byte) []byte {
	t.Helper()
	return spliceUPXChain(t, original, 64<<10, blockFor(t, []byte("junk")))
}

// spliceUPXChain is spliceFakeUPXHeader with a caller-supplied p_filesize and b_info chain, so a test can
// choose whether the fake header lands on a clean short reconstruction, one that gives something up, or a
// refusal by the size bounds with nothing unpacked at all.
func spliceUPXChain(t *testing.T, original []byte, originalSize uint32, chain []byte) []byte {
	t.Helper()

	header := buildUPXHeader(originalSize, 4096)[64:] // drop the stub, the real ELF header is already here
	block := chain
	need := len(header) + len(block)

	shoff := binary.LittleEndian.Uint64(original[0x28:0x30])
	shentsize := binary.LittleEndian.Uint16(original[0x3a:0x3c])
	shnum := binary.LittleEndian.Uint16(original[0x3c:0x3e])
	after := int(shoff) + int(shentsize)*int(shnum)

	at := -1
	for i := after; i+need <= upxMagicScanWindow && i+need <= len(original); i++ {
		if bytes.Equal(original[i:i+need], make([]byte, need)) {
			at = i
			break
		}
	}
	require.GreaterOrEqual(t, at, 0, "no padding in the scan window big enough to splice a header into")

	spiked := append([]byte(nil), original...)
	copy(spiked[at:], header)
	copy(spiked[at+len(header):], block)

	// the splice must not have broken the binary, or the fallback below would be covering for a corrupt
	// ELF rather than for a fake header. A claim the size bounds refuse is a deliberate caller choice, so
	// only assert the header parses when it was meant to.
	if originalSize <= maxUPXOriginalSize {
		require.NotNil(t, mustParseUPX(t, spiked), "the spliced header has to actually parse as UPX")
	}
	return spiked
}

// mustParseUPX reports the UPX header the scan finds in data, proving the splice is what the parser sees.
func mustParseUPX(t *testing.T, data []byte) *upxInfo {
	t.Helper()
	r := bytes.NewReader(data)
	info, err := parseUPXInfo(r, int64(len(data)))
	require.NoError(t, err)
	return info
}

func TestScanFile_FakeUPXHeaderStillYieldsPackages(t *testing.T) {
	// the same evasion one layer out, at the entry point the cataloger calls. The header has to actually be
	// spliced: run this against the untouched binary and it passes with the fallback deleted.
	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir()))
	original := goELF64Fixture(t)

	spiked := spliceFakeUPXHeader(t, original)

	ur, err := unionreader.GetUnionReader(io.NopCloser(bytes.NewReader(spiked)))
	require.NoError(t, err)

	builds, _ := scanFile(ctx, file.NewLocation("hello-linux-ppc64le"), ur, false)
	require.NotEmpty(t, builds, "a Go binary must not be hidden by four bytes of fake magic")
	for _, b := range builds {
		assert.Nil(t, b.unpacked,
			"the reconstruction carried nothing, so the scan has to fall back to the bytes as they were found")
		_ = b.unpacked.Close()
	}
}

// TestScanReader_CancellationStopsTheScan pins the direction a swallowed ctx.Err() got wrong. Cancellation
// is not a gap in the SBOM, so it is not reported as an unknown, but it does mean stop: returning "nothing
// to unpack, no error" sent the scan on to parse the packed bytes and build packages out of them after the
// caller had already called it off.
func TestScanReader_CancellationStopsTheScan(t *testing.T) {
	// enough blocks that the loop checks ctx at least once
	blocks := make([][]byte, 64)
	for i := range blocks {
		blocks[i] = bytes.Repeat([]byte("A"), 1024)
	}
	fixture := buildUPXFile(t, 64*1024, 4096, blocks, nil)

	ctx, cancel := context.WithCancel(tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir())))
	cancel()

	build, err := scanReader(ctx, file.NewLocation("/cancelled"), bytes.NewReader(fixture), false)
	assert.Nil(t, build)
	require.Error(t, err, "a cancelled scan has to stop rather than fall through to the packed bytes")
	assert.ErrorIs(t, err, context.Canceled)
	coordErrs, _ := unknown.ExtractCoordinateErrors(err)
	assert.Empty(t, coordErrs, "cancellation is not a gap in the SBOM")
}

// TestScanReader_SizeRefusalIsReported covers the reporting split for a header that really is UPX and
// claims more than the bounds allow. That is a file we declined to expand, which is the same category as
// elfutil.ErrDeclaredSizeExceeded and gets the same unknown. The ratio clears a measured 209x worst case at
// 256, so a legitimate binary crossing it must not vanish from the SBOM silently.
func TestScanReader_SizeRefusalIsReported(t *testing.T) {
	// a 4KB input claiming 512MB: pays no ratio and clears no ceiling
	data := padTo(buildUPXHeader(maxUPXOriginalSize, 0x1000), 4096)

	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir()))
	build, err := scanReader(ctx, file.NewLocation("/refused"), bytes.NewReader(data), false)

	assert.Nil(t, build)
	require.Error(t, err)
	coordErrs, _ := unknown.ExtractCoordinateErrors(err)
	require.NotEmpty(t, coordErrs,
		"a file we declined to expand is a gap we chose to leave, so it is reported")
	assert.ErrorIs(t, coordErrs[0].Reason, errUPXSizeRefused)
}

// corruptLZMABlock builds a b_info whose stream carries valid LZMA parameters and nothing else that
// decodes. This is what the loader stub behind the last real block looks like to readChainBlock: the
// method byte is one we implement and the sizes are in range, so the chain accepts it and the decoder is
// the thing that says no.
func corruptLZMABlock(szUnc uint32) []byte {
	stream := make([]byte, 64)
	stream[0] = 0x00 // pb = 0
	stream[1] = 0x00 // lc = 0, lp = 0
	for i := 2; i < len(stream); i++ {
		stream[i] = byte(i * 7) // not a range-coded anything
	}
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:4], szUnc)
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(stream)))
	b[8] = 14 // b_method = LZMA
	return append(b, stream...)
}

// TestDecompressUPX_UndecodableLaterBlockKeepsWhatCameBefore covers a chain that gives up a good
// reconstruction over garbage past the end of it.
//
// readChainBlock accepts any b_info-shaped run of bytes whose method it knows and whose sizes fit the
// file, so the loader stub behind the last real block parses as a block roughly one time in 256 on the
// method byte alone. A decode failure on that block must not discard every block already placed and turn a
// fully recoverable binary into zero packages: the two sibling conditions on the same block (an overrun,
// and a placement that does not fit) already keep their partial output, and this one must too.
func TestDecompressUPX_UndecodableLaterBlockKeepsWhatCameBefore(t *testing.T) {
	head := bytes.Repeat([]byte("H"), 256)

	data := buildUPXHeader(4096, 4096)
	data = append(data, blockFor(t, head)...)
	data = append(data, corruptLZMABlock(64)...)
	data = padTo(data, 1024)

	out, err := unpack(t, data)
	require.ErrorIs(t, err, errUPXPartial, "the blocks already placed are kept, and what was lost is reported")
	require.NotErrorIs(t, err, errUPXDecompress, "a good reconstruction is not discarded over trailing garbage")
	require.NotNil(t, out)

	assert.Equal(t, head, readAll(t, out), "everything decoded before the bad block stays placed")
}

// TestDecompressUPX_UndecodableFirstBlockStillFailsTheFile is the other half: with nothing placed there is
// no partial output to keep, so the file really is one we could not unpack.
func TestDecompressUPX_UndecodableFirstBlockStillFailsTheFile(t *testing.T) {
	data := padTo(append(buildUPXHeader(4096, 4096), corruptLZMABlock(64)...), 1024)

	_, err := unpack(t, data)
	require.ErrorIs(t, err, errUPXDecompress, "a packed file with nothing readable in it is a gap in the SBOM")
	assert.NotErrorIs(t, err, errUPXPartial)
}

// TestScanReader_PartialReconstructionIsReported is the regression test for a partial unpack vanishing
// silently. The reconstruction is truncated to the contiguous prefix, which is the right bound, but the
// bytes past the gap are gone: on a real binary that is the non-loadable tail holding the section headers,
// so the symbols and often the build info go with it. Reported at Trace, the binary contributed no
// packages and no unknown, which is the one outcome the reporting split in upx.go exists to prevent.
func TestScanReader_PartialReconstructionIsReported(t *testing.T) {
	const declared = 64 << 20
	data := sparseFixture(t, declared, declared-64, 0, 300_000)

	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir()))
	build, err := scanReader(ctx, file.NewLocation("/partial"), bytes.NewReader(data), false)

	assert.Nil(t, build)
	require.Error(t, err)
	coordErrs, _ := unknown.ExtractCoordinateErrors(err)
	require.NotEmpty(t, coordErrs, "a reconstruction that lost bytes is a gap this cataloger chose to leave")
	assert.ErrorIs(t, coordErrs[0].Reason, errUPXPartial)
}

// TestReadContentsAndBuildInfo_FallbackToFoundBytesReportsNoGap pins the retry direction. A gap is
// reported because the readers after it (crypto settings, arch, symbols) would otherwise read a short
// reconstruction with nothing saying so, which is what
// TestReadContentsAndBuildInfo_GapSurvivesBuildInfoFromTheReconstruction covers. That reasoning runs out
// here: the retry hands back the bytes as they were found, every reader below reads those, and the header
// that produced the short reconstruction was not describing real UPX output to begin with. Reporting it
// would put "UPX reconstruction is incomplete" on a binary that was never packed and was read in full.
func TestReadContentsAndBuildInfo_FallbackToFoundBytesReportsNoGap(t *testing.T) {
	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir()))

	// a chain that decodes one block and then hits a block it cannot read: the reconstruction is real but
	// short, and the build info comes from the fallback to the bytes as they were found
	chain := append(blockFor(t, []byte("junk")), corruptLZMABlock(64)...)
	spiked := spliceUPXChain(t, goELF64Fixture(t), 64<<10, chain)

	unpacked, bi, err := readContentsAndBuildInfo(ctx, bytes.NewReader(spiked))
	t.Cleanup(func() { _ = unpacked.Close() })

	require.NotNil(t, bi, "the fallback still finds the build info")
	require.Nil(t, unpacked, "the reconstruction was released; the caller reads the bytes as they were found")
	assert.NoError(t, err, "nothing downstream reads the short reconstruction, so there is no gap to report")
}

// TestUnpackUPX_CancelledContextComesBackAsCtxErr covers the cancellation arm in unpackUPX directly: the
// scan-level test above it passes even with this arm deleted, since readContentsAndBuildInfo does not
// re-check ctx.Err() on its own.
func TestUnpackUPX_CancelledContextComesBackAsCtxErr(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 2048)
	blocks := make([][]byte, 64)
	for i := range blocks {
		blocks[i] = payload
	}
	data := padTo(buildUPXFile(t, 4096*64, 2048, blocks, nil), 4096)

	ctx, cancel := context.WithCancel(tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir())))
	cancel()

	out, err := unpackUPX(ctx, bytes.NewReader(data))
	require.ErrorIs(t, err, context.Canceled)
	assert.NotErrorIs(t, err, errUPXDecompress, "a cancelled scan is not a gap in the SBOM")
	assert.NotErrorIs(t, err, errUPXPartial, "nor is it a short reconstruction")
	assert.Nil(t, out, "a cancelled unpack hands back nothing; the caller reads the input as it was found")
}

// TestParseUPXInfo_HeaderRunsPastTheScanWindow covers the guard on the l_info+p_info read: the magic can
// sit close enough to the end of what was actually read that the 20 bytes behind it are not there.
func TestParseUPXInfo_HeaderRunsPastTheScanWindow(t *testing.T) {
	data := append(packedELFStub(), upxMagic...) // magic at 64, nothing behind it

	r := bytes.NewReader(data)
	_, err := parseUPXInfo(r, int64(len(data)))
	require.Error(t, err)
	assert.ErrorIs(t, err, errUPXImplausibleHeader)
	assert.NotErrorIs(t, err, errUPXSizeRefused, "a header we could not even read is not a refusal to expand")
}

// TestReadContentsAndBuildInfo_GapSurvivesBuildInfoFromTheReconstruction is the same property one path
// over: here the reconstruction itself carries the build info, so the early return must not throw the
// unpack error away. The chain rebuilds a whole Go binary and then hits a block it cannot read, which is
// exactly the shape of a real packed binary whose tail extents did not all come back.
func TestReadContentsAndBuildInfo_GapSurvivesBuildInfoFromTheReconstruction(t *testing.T) {
	payload := goELF64Fixture(t)

	data := buildUPXHeader(uint32(len(payload)+64), 4096)
	data = append(data, blockFor(t, payload)...)
	data = append(data, corruptLZMABlock(64)...)

	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir()))
	contents, bi, err := readContentsAndBuildInfo(ctx, bytes.NewReader(data))
	require.NotNil(t, contents)
	t.Cleanup(func() { _ = contents.Close() })

	require.NotNil(t, contents, "the build info has to come from the reconstruction here")
	require.NotNil(t, bi, "the rebuilt binary is a whole Go binary")
	assert.ErrorIs(t, err, errUPXPartial,
		"the block the chain gave up is still a gap, even though the build info came through")
}

// TestScanReader_PartialReconstructionStillYieldsItsPackages is the other direction of the reporting
// split, and the one that keeps the new reporting from becoming a regression of its own: a gap is
// something to report alongside the packages, not instead of them. A binary whose chain gave up its tail
// still has its module list, and dropping it would trade a silent false negative for a loud one.
func TestScanReader_PartialReconstructionStillYieldsItsPackages(t *testing.T) {
	payload := goELF64Fixture(t)

	data := buildUPXHeader(uint32(len(payload)+64), 4096)
	data = append(data, blockFor(t, payload)...)
	data = append(data, corruptLZMABlock(64)...)

	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir()))
	build, err := scanReader(ctx, file.NewLocation("/partial-but-usable"), bytes.NewReader(data), false)

	require.NotNil(t, build, "a reported gap must not cost the packages that did come through")
	t.Cleanup(func() { _ = build.unpacked.Close() })
	assert.NotNil(t, build.BuildInfo)

	require.Error(t, err)
	coordErrs, _ := unknown.ExtractCoordinateErrors(err)
	require.NotEmpty(t, coordErrs, "and the gap is still reported")
	assert.ErrorIs(t, coordErrs[0].Reason, errUPXPartial)
}

// sizeProbeSpy counts the size probes made against it. intFile.ReaderSize answers from Size() when the
// reader has one, which is what this intercepts.
type sizeProbeSpy struct {
	*bytes.Reader
	probes int
}

func (s *sizeProbeSpy) Size() int64 {
	s.probes++
	return s.Reader.Size()
}

// TestUnpackUPX_ContainerGateComesBeforeTheSizeProbe pins the ordering that keeps this cheap. The
// cataloger runs over every file in an image and almost none are packed ELF, so nothing above the six
// byte ident check should cost more than that: ReaderSize seeks to the end and reads the last byte back,
// which over a squashfs or tar-backed reader is a real seek and decompress.
func TestUnpackUPX_ContainerGateComesBeforeTheSizeProbe(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		probed bool
	}{
		{name: "not an ELF at all", data: bytes.Repeat([]byte("just some bytes"), 64)},
		{name: "a 32-bit ELF", data: func() []byte { b := padTo(packedELFStub(), 256); b[4] = 1; return b }()},
		{name: "a big-endian ELF64", data: func() []byte { b := padTo(packedELFStub(), 256); b[5] = 2; return b }()},
		{name: "an ELF64 we would try to unpack", data: padTo(packedELFStub(), 256), probed: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &sizeProbeSpy{Reader: bytes.NewReader(tt.data)}
			out, err := unpackUPX(context.Background(), spy)
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

			if tt.probed {
				assert.Positive(t, spy.probes, "a candidate container does get measured")
				return
			}
			assert.Zero(t, spy.probes, "a file we will never unpack must not be measured first")
		})
	}
}

// TestScanReader_ChainEndingShortIsReported covers the fourth shape a short reconstruction comes in: a
// chain that simply ran out of b_info structures before rebuilding p_filesize must be reported, the same
// as one that gave up mid-walk, one that hit the block cap, and one with blocks stranded past a hole. Every
// quiet exit in readChainBlock produces that shape (an unreadable b_info, the end marker, a zero sz_cpr,
// compressed data past the end of the input, an unimplemented method past the first block), and the
// reconstruction is then truncated to the covered prefix, which can drop the section headers and leave the
// binary contributing neither packages nor an unknown.
func TestScanReader_ChainEndingShortIsReported(t *testing.T) {
	// one 2048 byte block against a declared 4096, then the end marker: nothing failed, the chain just ran
	// out. stopped is nil, covered equals the furthest placement, and covered is half of total.
	payload := bytes.Repeat([]byte("A"), 2048)
	data := buildUPXHeader(4096, 2048)
	data = append(data, blockFor(t, payload)...)
	data = append(data, make([]byte, 12)...) // end marker
	data = padTo(data, 512)

	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir()))
	build, err := scanReader(ctx, file.NewLocation("/short-chain"), bytes.NewReader(data), false)

	assert.Nil(t, build)
	require.Error(t, err)
	coordErrs, _ := unknown.ExtractCoordinateErrors(err)
	require.NotEmpty(t, coordErrs, "a chain that ended before rebuilding p_filesize is a reported gap")
	assert.ErrorIs(t, coordErrs[0].Reason, errUPXPartial)
}

// TestScanReader_SizeRefusalOnAnUnpackedBinaryIsNotReported is the other direction of
// TestScanReader_SizeRefusalIsReported. The magic is found by an unanchored scan over the first 8KB, so an
// ordinary Go binary can carry a "UPX!" that parses into a header the size bounds then refuse. Nothing is
// unpacked in that case: unpackUPX hands back the input exactly as it was found, every reader below reads
// those bytes in full, and the build info proves they are complete. Reporting the refusal there put
// "golang binary read incompletely" on a binary the cataloger read completely, with every package present.
func TestScanReader_SizeRefusalOnAnUnpackedBinaryIsNotReported(t *testing.T) {
	original := goELF64Fixture(t)
	// a header whose p_filesize no input this size could ever pay for, so parseUPXInfo refuses it before
	// decompressUPX is reached and there is no reconstruction at any point
	spiked := spliceUPXChain(t, original, 0xFFFFFFFF, blockFor(t, []byte("junk")))

	_, perr := parseUPXInfo(bytes.NewReader(spiked), int64(len(spiked)))
	require.ErrorIs(t, perr, errUPXSizeRefused, "the splice has to be refused by the size bounds")

	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir()))
	build, err := scanReader(ctx, file.NewLocation("/spiked"), bytes.NewReader(spiked), false)
	if build != nil {
		t.Cleanup(func() { _ = build.unpacked.Close() })
	}

	require.NotNil(t, build, "the binary is a complete Go binary and must still be cataloged")
	assert.Nil(t, build.unpacked, "nothing was unpacked, so these are the bytes as found")
	coordErrs, _ := unknown.ExtractCoordinateErrors(err)
	assert.Empty(t, coordErrs, "a file read in full must not be reported as read incompletely")
}

// TestDecompressUPX_DenseChainReportsNoGap is the guard for the covered >= total early return in
// finalExtent, and it is the fixture every other one in this package is not: dense. A chain that rebuilds
// exactly p_filesize must come back with no partial reason attached.
//
// This matters because reporting a chain that ended short (the arm below that early return) is only safe if
// well-formed output reaches full coverage. Every other crafted fixture here declares more than it delivers
// and asserts errUPXPartial, and the one test that sees real `upx --best --lzma` output needs Docker, so
// without this the early return has no local guard and the new arm's false-positive risk is untested.
//
// Layout below tiles 320 bytes through all three placement rules: block 1 at zero, block 2 sequentially
// behind it, block 3 at a PT_LOAD offset from the headers in block 1, and block 4 into the hole those left.
func TestDecompressUPX_DenseChainReportsNoGap(t *testing.T) {
	const (
		headerBlock = 64 + 112 // ELF64 header plus two program headers
		block2Size  = 24       // sequential, so [176, 200)
		ptLoad1     = 256      // block 3 lands here, leaving [200, 256) behind
		block3Size  = 64       // [256, 320)
		holeSize    = ptLoad1 - (headerBlock + block2Size)
		total       = ptLoad1 + block3Size
	)

	phdrs := make([]byte, 112)
	binary.LittleEndian.PutUint32(phdrs[0:4], 1)  // phdr[0] PT_LOAD
	binary.LittleEndian.PutUint64(phdrs[8:16], 0) // p_offset 0, the extent block 2 covers
	binary.LittleEndian.PutUint32(phdrs[56:60], 1)
	binary.LittleEndian.PutUint64(phdrs[64:72], ptLoad1) // phdr[1] p_offset, where block 3 goes

	block1 := buildELF64(64, 56, 2, phdrs)
	require.Len(t, block1, headerBlock, "the first block is the original ELF headers")

	data := buildUPXHeader(total, 4096)
	data = append(data, blockFor(t, block1)...)                                // placed at 0
	data = append(data, blockFor(t, bytes.Repeat([]byte("S"), block2Size))...) // sequential
	data = append(data, blockFor(t, bytes.Repeat([]byte("P"), block3Size))...) // -> ptLoadOffsets[1]
	data = append(data, blockFor(t, bytes.Repeat([]byte("F"), holeSize))...)   // -> firstHole
	data = append(data, make([]byte, 12)...)                                   // end marker
	data = padTo(data, 1024)

	out, err := unpack(t, data)
	require.NotNil(t, out)
	require.NoError(t, err,
		"a chain that rebuilt every byte p_filesize declared has given nothing up, so there is no gap to report")

	got := readAll(t, out)
	assert.Len(t, got, total, "the reconstruction is exactly what was declared")
	assert.Equal(t, bytes.Repeat([]byte("F"), holeSize), got[headerBlock+block2Size:ptLoad1],
		"the hole between the sequential extent and the PT_LOAD one is filled by the block after them")
	assert.Equal(t, bytes.Repeat([]byte("P"), block3Size), got[ptLoad1:],
		"block 3 lands at the PT_LOAD offset the headers declared")
}

// TestFinalExtent pins which reason a short reconstruction comes back with, not merely that it is short.
// Every arm wraps errUPXPartial and nothing else read the messages, so three of the four were
// interchangeable: deleting the block-cap arm and the stranded-blocks arm left the whole package green
// because both fell through to the arm below them. finalExtent is a pure function, so this costs nothing.
func TestFinalExtent(t *testing.T) {
	tests := []struct {
		name     string
		covered  uint64
		blockNum int
		total    uint64
		stopped  error
		wantMsg  string // empty means no gap is reported
	}{
		{
			name:     "a chain that rebuilt everything reports nothing, whatever it tripped over next",
			covered:  100,
			blockNum: 2,
			total:    100,
			stopped:  fmt.Errorf("%w: ignored once coverage is complete", errUPXPartial),
		},
		{
			name:     "a mid-walk stop is more specific than anything the extents show",
			covered:  100,
			blockNum: 2,
			total:    200,
			stopped:  fmt.Errorf("%w: block 2 did not decode", errUPXPartial),
			wantMsg:  "block 2 did not decode",
		},
		{
			name:     "hitting the block cap is named as the cap",
			covered:  100,
			blockNum: maxUPXBlocks,
			total:    200,
			wantMsg:  "block cap",
		},
		{
			name:     "a chain that simply ended is named as such",
			covered:  100,
			blockNum: 3,
			total:    200,
			wantMsg:  "chain ended after 100 of the declared 200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := finalExtent(tt.covered, tt.blockNum, tt.total, tt.stopped)

			if tt.wantMsg == "" {
				assert.NoError(t, got)
				return
			}
			require.Error(t, got)
			assert.ErrorIs(t, got, errUPXPartial)
			assert.Contains(t, got.Error(), tt.wantMsg,
				"the reason has to say which shape this was, or the arms are interchangeable")
		})
	}
}

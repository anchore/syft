package pe

import (
	"bytes"
	"debug/pe"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	intFile "github.com/anchore/syft/internal/file"
)

func TestReadDataFromRVA_BogusSizeDoesNotOverAllocate(t *testing.T) {
	// size comes from the PE headers and spans the full uint32 range. Sizing the buffer from it up front
	// let a tiny file reserve 4GB, so the shortfall has to be caught before the allocation: the read stays
	// a single exactly-sized one, and a size the file cannot back is an error rather than a mostly-zero
	// buffer returned as if it had been filled.
	const fileSize = 512
	sections := []pe.SectionHeader32{{VirtualAddress: 0x1000, VirtualSize: 0x1000, PointerToRawData: 0}}
	r := &readSizeRecorder{Reader: bytes.NewReader(make([]byte, fileSize))}

	var err error
	allocated := measureAlloc(t, func() {
		_, err = readDataFromRVA(r, 0x1000, 0xFFFFFFFF, sections)
	})

	require.Error(t, err, "a size the file cannot satisfy must not be reported as a successful read")
	assert.Less(t, allocated, uint64(intFile.MB),
		"the declared 4GB must never be reserved; the shortfall has to be caught before the allocation")
	assert.LessOrEqual(t, r.maxRead, fileSize,
		"no single read may exceed the file size, regardless of what the headers claim")
}

func TestReadDataFromRVA_ReadsFullyWhenSizeFits(t *testing.T) {
	// the bound must not truncate a legitimate read
	sections := []pe.SectionHeader32{{VirtualAddress: 0x1000, VirtualSize: 0x1000, PointerToRawData: 0}}
	want := bytes.Repeat([]byte("z"), 128)

	got, err := readDataFromRVA(bytes.NewReader(want), 0x1000, uint32(len(want)), sections)
	require.NoError(t, err)
	assert.Equal(t, int64(len(want)), got.Size())
}

func TestReadDataFromRVA_StopsAtSizeInALargerFile(t *testing.T) {
	// a file exactly `size` bytes long cannot distinguish a bounded read from an unbounded one, since the
	// read stops at EOF either way. Only a file with bytes past `size` pins the limit.
	sections := []pe.SectionHeader32{{VirtualAddress: 0x1000, VirtualSize: 0x2000, PointerToRawData: 0}}
	const size = 128
	file := append(bytes.Repeat([]byte("z"), size), bytes.Repeat([]byte("!"), 4096)...)
	r := &readSizeRecorder{Reader: bytes.NewReader(file)}

	got, err := readDataFromRVA(r, 0x1000, size, sections)
	require.NoError(t, err)

	data := make([]byte, got.Size())
	_, err = got.ReadAt(data, 0)
	require.NoError(t, err)
	assert.Equal(t, bytes.Repeat([]byte("z"), size), data,
		"the read must stop at size rather than running on into the rest of the file")
	assert.LessOrEqual(t, r.maxRead, size, "no read may request more than the declared size")
}

func TestReadDataFromRVA_SizePastTheAbsoluteCapIsRejected(t *testing.T) {
	// clamping to the bytes remaining in the file is not enough on its own: a mostly empty file costs
	// almost nothing inside a compressed layer, so a cheap artifact can still declare a directory large
	// enough to OOM the scan. The absolute cap is what bounds that, and it has to run before the
	// allocation like every other bound here.
	const size = maxDirectorySectionSize + 1
	sections := []pe.SectionHeader32{{VirtualAddress: 0x1000, VirtualSize: 0x1000, PointerToRawData: 0}}

	// a sparse file that really is large enough to satisfy the declared size
	r := &readSizeRecorder{Reader: bytes.NewReader(make([]byte, size+1))}

	var err error
	allocated := measureAlloc(t, func() {
		_, err = readDataFromRVA(r, 0x1000, size, sections)
	})

	require.ErrorContains(t, err, "exceeds the")
	assert.Less(t, allocated, uint64(intFile.MB),
		"the cap has to be checked before the buffer is sized, not after")
}

func TestReadDataFromRVA_SizeAtTheAbsoluteCapIsAllowed(t *testing.T) {
	// the cap must not reject what it is meant to permit, so pin the boundary from the other side. Only the
	// requested read length is checked here; allocating the full cap would make the test cost of this the
	// same as the bug it guards against.
	sections := []pe.SectionHeader32{{VirtualAddress: 0x1000, VirtualSize: 0x1000, PointerToRawData: 0}}

	// one byte short of the cap, in a file that cannot back it: the size check has to pass and the
	// remaining-bytes check has to be what rejects it
	r := &readSizeRecorder{Reader: bytes.NewReader(make([]byte, 512))}

	_, err := readDataFromRVA(r, 0x1000, maxDirectorySectionSize-1, sections)
	require.ErrorContains(t, err, "only 512 remain",
		"a size under the cap must fall through to the remaining-bytes check, not be capped away")
}

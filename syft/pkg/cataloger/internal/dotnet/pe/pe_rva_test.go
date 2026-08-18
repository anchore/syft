package pe

import (
	"bytes"
	"debug/pe"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadDataFromRVA_BogusSizeDoesNotOverAllocate(t *testing.T) {
	// size comes from the PE headers and spans the full uint32 range. Sizing the buffer from it up front
	// let a tiny file reserve 4GB; the read must instead grow to what the file holds and then report the
	// shortfall rather than returning a mostly-zero buffer as if it had been filled.
	const fileSize = 512
	sections := []pe.SectionHeader32{{VirtualAddress: 0x1000, VirtualSize: 0x1000, PointerToRawData: 0}}
	r := &readSizeRecorder{Reader: bytes.NewReader(make([]byte, fileSize))}

	var err error
	allocated := measureAlloc(t, func() {
		_, err = readDataFromRVA(r, 0x1000, 0xFFFFFFFF, sections)
	})

	require.Error(t, err, "a size the file cannot satisfy must not be reported as a successful read")
	assert.Less(t, allocated, uint64(1<<20),
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
	// a file exactly `size` bytes long cannot distinguish a bounded read from an unbounded one, since
	// io.ReadAll stops at EOF either way. Only a file with bytes past `size` pins the limit.
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

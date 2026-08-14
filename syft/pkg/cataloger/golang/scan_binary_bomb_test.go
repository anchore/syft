package golang

import (
	"bytes"
	"compress/zlib"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

// Test_getBuildInfo_compressedSectionBomb covers the reason readBuildInfo exists: debug/buildinfo opens
// ELF files with debug/elf itself, and elf.NewFile expands the section-name string table as it parses,
// so an oversized compression header there is an unbounded allocation on a path elfutil.NewFile never
// sees. The fixture is a real zlib stream, so it delivers every byte its header promises.
func Test_getBuildInfo_compressedSectionBomb(t *testing.T) {
	const declared = 256 << 20 // comfortably over elfutil's bound, small enough to allocate in a test

	bomb := elfWithCompressedNameTable(t, declared)
	t.Logf("%d byte fixture declares a %d byte section name table", len(bomb), declared)

	// the unguarded path is the thing being defended against: prove the fixture really is a bomb
	unguarded := measureAlloc(t, func() {
		_, err := buildinfo.Read(bytes.NewReader(bomb))
		t.Logf("buildinfo.Read err: %v", err)
	})
	assert.Greater(t, unguarded, uint64(declared), "fixture did not actually deliver the declared bytes")

	guarded := measureAlloc(t, func() {
		_, err := getBuildInfo(bytes.NewReader(bomb), file.NewLocation("bomb"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "over the")
	})
	assert.Less(t, guarded, uint64(32<<20), "getBuildInfo allocated far more than the input warrants")
	t.Logf("unguarded allocated %d bytes, guarded allocated %d bytes", unguarded, guarded)
}

func measureAlloc(t *testing.T, fn func()) uint64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// elfWithCompressedNameTable builds a minimal ELF64 whose only real section is a SHF_COMPRESSED
// .shstrtab declaring `declared` decompressed bytes and genuinely delivering them.
func elfWithCompressedNameTable(t *testing.T, declared uint64) []byte {
	t.Helper()

	// the decompressed name table only has to start with the section names; the rest is padding that
	// exists purely to make the declared size real
	payload := make([]byte, declared)
	copy(payload, "\x00.shstrtab\x00")

	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	_, err := zw.Write(payload)
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	ehsize := uint64(binary.Size(elf.Header64{}))
	shentsize := uint64(binary.Size(elf.Section64{}))
	chdrsize := uint64(binary.Size(elf.Chdr64{}))
	shoff := ehsize
	bodyOff := shoff + 2*shentsize

	var ident [16]byte
	copy(ident[:], elf.ELFMAG)
	ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)

	buf := &bytes.Buffer{}
	require.NoError(t, binary.Write(buf, binary.LittleEndian, elf.Header64{
		Ident: ident, Type: uint16(elf.ET_REL), Machine: uint16(elf.EM_X86_64),
		Version: uint32(elf.EV_CURRENT), Shoff: shoff, Ehsize: uint16(ehsize),
		Shentsize: uint16(shentsize), Shnum: 2, Shstrndx: 1,
	}))
	// the null section
	require.NoError(t, binary.Write(buf, binary.LittleEndian, elf.Section64{}))
	// the name table: sh_size is the on-disk size, so it has to cover the whole zlib stream
	require.NoError(t, binary.Write(buf, binary.LittleEndian, elf.Section64{
		Name: 1, Type: uint32(elf.SHT_STRTAB), Flags: uint64(elf.SHF_COMPRESSED),
		Off: bodyOff, Size: chdrsize + uint64(compressed.Len()), Addralign: 1,
	}))
	require.NoError(t, binary.Write(buf, binary.LittleEndian, elf.Chdr64{
		Type: uint32(elf.COMPRESS_ZLIB), Size: declared, Addralign: 1,
	}))
	buf.Write(compressed.Bytes())

	return buf.Bytes()
}

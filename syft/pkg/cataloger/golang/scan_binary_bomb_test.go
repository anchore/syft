package golang

import (
	"bytes"
	"compress/zlib"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"os"
	"runtime"
	"testing"

	"github.com/kastenhq/goversion/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/internal/elfutil"
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
		_, err := getBuildInfo(bytes.NewReader(bomb))
		require.Error(t, err)
		assert.ErrorIs(t, err, elfutil.ErrDeclaredSizeExceeded)
	})
	assert.Less(t, guarded, uint64(32<<20), "getBuildInfo allocated far more than the input warrants")
	t.Logf("unguarded allocated %d bytes, guarded allocated %d bytes", unguarded, guarded)
}

// Test_getCryptoInformation_compressedSymtabBomb covers the second unbounded door into debug/elf:
// goversion opens the file itself and reads .symtab plus the string table it links, and those are
// expanded lazily, so the section-name table bound getBuildInfo applies never reaches them.
func Test_getCryptoInformation_compressedSymtabBomb(t *testing.T) {
	const declared = 256 << 20 // comfortably over elfutil's bound, small enough to allocate in a test

	bomb := elfWithCompressedSymtab(t, declared)
	t.Logf("%d byte fixture declares a %d byte symbol table", len(bomb), declared)

	// the unguarded path is the thing being defended against: prove the fixture really is a bomb
	unguarded := measureAlloc(t, func() {
		_, err := version.ReadExeFromReader(bytes.NewReader(bomb))
		t.Logf("goversion err: %v", err)
	})
	assert.Greater(t, unguarded, uint64(declared), "fixture did not actually deliver the declared bytes")

	guarded := measureAlloc(t, func() {
		_, err := getCryptoInformation(bytes.NewReader(bomb))
		require.ErrorIs(t, err, elfutil.ErrDeclaredSizeExceeded)
	})
	assert.Less(t, guarded, uint64(32<<20), "getCryptoInformation allocated far more than the input warrants")
	t.Logf("unguarded allocated %d bytes, guarded allocated %d bytes", unguarded, guarded)
}

// Test_getCryptoInformation_passesThroughNonELF keeps the gate from becoming a container filter: goversion
// reads PE and Mach-O too, and CheckAllSections has to leave those to it.
func Test_getCryptoInformation_passesThroughNonELF(t *testing.T) {
	runMakeTarget(t, "archs")

	for _, name := range []string{"hello-win-amd64", "hello-mach-o-arm64"} {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open("testdata/archs/binaries/" + name)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, f.Close()) })

			_, err = getCryptoInformation(f)
			require.NoError(t, err)
		})
	}
}

// elfWithCompressedSymtab builds a minimal ELF64 whose .symtab is SHF_COMPRESSED, declaring `declared`
// decompressed bytes and genuinely delivering them. The name table is left uncompressed so the file gets
// past the bound getBuildInfo already applies, which is the point: this is the section that bound misses.
func elfWithCompressedSymtab(t *testing.T, declared uint64) []byte {
	t.Helper()

	payload := make([]byte, declared)
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	_, err := zw.Write(payload)
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	names := []byte("\x00.shstrtab\x00.symtab\x00.strtab\x00")
	nameOf := func(s string) uint32 {
		i := bytes.Index(names, []byte("\x00"+s+"\x00"))
		require.GreaterOrEqual(t, i, 0)
		return uint32(i + 1)
	}

	ehsize := uint64(binary.Size(elf.Header64{}))
	shentsize := uint64(binary.Size(elf.Section64{}))
	chdrsize := uint64(binary.Size(elf.Chdr64{}))
	shoff := ehsize
	namesOff := shoff + 4*shentsize
	symOff := namesOff + uint64(len(names))
	symSize := chdrsize + uint64(compressed.Len())
	strOff := symOff + symSize

	var ident [16]byte
	copy(ident[:], elf.ELFMAG)
	ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)

	buf := &bytes.Buffer{}
	require.NoError(t, binary.Write(buf, binary.LittleEndian, elf.Header64{
		Ident: ident, Type: uint16(elf.ET_REL), Machine: uint16(elf.EM_X86_64),
		Version: uint32(elf.EV_CURRENT), Shoff: shoff, Ehsize: uint16(ehsize),
		Shentsize: uint16(shentsize), Shnum: 4, Shstrndx: 1,
	}))
	// the null section
	require.NoError(t, binary.Write(buf, binary.LittleEndian, elf.Section64{}))
	require.NoError(t, binary.Write(buf, binary.LittleEndian, elf.Section64{
		Name: nameOf(".shstrtab"), Type: uint32(elf.SHT_STRTAB), Off: namesOff,
		Size: uint64(len(names)), Addralign: 1,
	}))
	// the bomb: sh_size covers the whole zlib stream, ch_size is what debug/elf expands to
	require.NoError(t, binary.Write(buf, binary.LittleEndian, elf.Section64{
		Name: nameOf(".symtab"), Type: uint32(elf.SHT_SYMTAB), Flags: uint64(elf.SHF_COMPRESSED),
		Off: symOff, Size: symSize, Link: 3, Entsize: 24, Addralign: 1,
	}))
	require.NoError(t, binary.Write(buf, binary.LittleEndian, elf.Section64{
		Name: nameOf(".strtab"), Type: uint32(elf.SHT_STRTAB), Off: strOff, Size: 1, Addralign: 1,
	}))
	buf.Write(names)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, elf.Chdr64{
		Type: uint32(elf.COMPRESS_ZLIB), Size: declared, Addralign: 1,
	}))
	buf.Write(compressed.Bytes())
	buf.Write([]byte{0})

	return buf.Bytes()
}

// measureAlloc reports the bytes allocated while fn ran. TotalAlloc is process-wide, so a test using this
// must not call t.Parallel: another test's allocations would land in the measurement.
func measureAlloc(t *testing.T, fn func()) uint64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// elfWithCompressedNameTable builds a minimal ELF64 whose only real section is a SHF_COMPRESSED .shstrtab
// declaring `declared` decompressed bytes and genuinely delivering them. Only the test that runs the
// unguarded path needs delivery; use elfDeclaringNameTable everywhere else, since building this one costs
// `declared` bytes of allocation plus a zlib compress of them.
func elfWithCompressedNameTable(t *testing.T, declared uint64) []byte {
	t.Helper()
	return elfNameTableFixture(t, declared, true)
}

// elfDeclaringNameTable declares `declared` bytes without delivering them. CheckSectionNameTable reads the
// declared size out of the compression header and refuses before decompressing anything, so a test of the
// bound itself never needs the stream to be real.
func elfDeclaringNameTable(t *testing.T, declared uint64) []byte {
	t.Helper()
	return elfNameTableFixture(t, declared, false)
}

func elfNameTableFixture(t *testing.T, declared uint64, deliver bool) []byte {
	t.Helper()

	// the decompressed name table only has to start with the section names; the rest is padding that
	// exists purely to make the declared size real
	size := declared
	if !deliver {
		size = 64
	}
	payload := make([]byte, size)
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

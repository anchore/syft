package golang

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/testutils"
)

// Test_getBuildInfo_SkipsELFWithoutBuildInfoSection covers the reason elfLacksBuildInfoSection exists:
// debug/buildinfo falls back to searching the whole writable segment of any ELF that has no .go.buildinfo
// section, allocating a 1MB buffer to do it, and this cataloger asks it to for every executable in an
// image. A section table that has no such section is proof the search would find nothing.
func Test_getBuildInfo_SkipsELFWithoutBuildInfoSection(t *testing.T) {
	const dataSize = 4 << 20 // the writable segment debug/buildinfo would otherwise search
	notGo := elfWithWritableSegment(t, dataSize, false)

	// the unguarded path is what is being avoided: prove the fixture really drives the search
	unguarded := testutils.MeasureAlloc(t, func() {
		_, err := buildinfo.Read(bytes.NewReader(notGo))
		require.EqualError(t, err, "not a Go executable")
	})
	assert.Greater(t, unguarded, uint64(1<<20), "fixture did not drive debug/buildinfo's segment search")

	var bi any
	guarded := testutils.MeasureAlloc(t, func() {
		got, err := getBuildInfo(bytes.NewReader(notGo))
		require.NoError(t, err)
		bi = got
	})
	assert.Nil(t, bi)
	assert.Less(t, guarded, uint64(64<<10), "the section check should cost a few KB, not a segment search")
	t.Logf("unguarded allocated %d bytes, guarded allocated %d bytes", unguarded, guarded)
}

func Test_elfLacksBuildInfoSection(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "sections without .go.buildinfo",
			input: elfWithWritableSegment(t, 4096, false),
			want:  true,
		},
		{
			name:  "sections with .go.buildinfo",
			input: elfWithWritableSegment(t, 4096, true),
			want:  false,
		},
		{
			name:  "no section table at all",
			input: withoutSectionTable(elfWithWritableSegment(t, 4096, false)),
			want:  false,
		},
		{
			name:  "not an ELF",
			input: []byte("MZ this is not an ELF file at all, and buildinfo gets to say so"),
			want:  false,
		},
		{
			name:  "truncated ELF",
			input: elfWithWritableSegment(t, 4096, false)[:40],
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, elfLacksBuildInfoSection(bytes.NewReader(tt.input)))
		})
	}
}

// Test_getBuildInfo_ReadsThisGoBinary uses the test binary itself as the Go binary: it was built by the
// toolchain running the test, so its build info is known without any fixture.
func Test_getBuildInfo_ReadsThisGoBinary(t *testing.T) {
	exe := thisELFBinary(t)
	defer exe.Close()

	bi, err := getBuildInfo(exe)
	require.NoError(t, err)
	require.NotNil(t, bi)
	assert.Equal(t, runtime.Version(), bi.GoVersion)
}

// Test_getBuildInfo_ReadsGoBinaryWithoutSectionTable is the case the section check must stand aside for:
// a Go binary whose section headers are gone (sstrip, or a UPX reconstruction) has no .go.buildinfo to
// find by name, and debug/buildinfo's segment search is the only way to read it.
func Test_getBuildInfo_ReadsGoBinaryWithoutSectionTable(t *testing.T) {
	exe := thisELFBinary(t)
	defer exe.Close()

	header := make([]byte, binary.Size(elf.Header64{}))
	_, err := exe.ReadAt(header, 0)
	require.NoError(t, err)
	stripped := &patchedReaderAt{ReaderAt: exe, patch: withoutSectionTable(header)}

	f, err := elf.NewFile(stripped)
	require.NoError(t, err)
	require.Empty(t, f.Sections, "the fixture should present no section table")
	assert.False(t, elfLacksBuildInfoSection(stripped))

	bi, err := getBuildInfo(stripped)
	require.NoError(t, err)
	require.NotNil(t, bi)
	assert.Equal(t, runtime.Version(), bi.GoVersion)
}

// thisELFBinary opens the running test binary, skipping on platforms where it is not an ELF.
func thisELFBinary(t *testing.T) *os.File {
	t.Helper()
	path, err := os.Executable()
	require.NoError(t, err)
	f, err := os.Open(path)
	require.NoError(t, err)
	var ident [4]byte
	_, err = f.ReadAt(ident[:], 0)
	require.NoError(t, err)
	if string(ident[:]) != elf.ELFMAG {
		f.Close()
		t.Skipf("the test binary is not an ELF on %s", runtime.GOOS)
	}
	return f
}

// patchedReaderAt serves patch in place of the first len(patch) bytes of the underlying reader.
type patchedReaderAt struct {
	io.ReaderAt
	patch []byte
}

func (p *patchedReaderAt) ReadAt(b []byte, off int64) (int, error) {
	n, err := p.ReaderAt.ReadAt(b, off)
	if off < int64(len(p.patch)) {
		copy(b[:n], p.patch[off:])
	}
	return n, err
}

// withoutSectionTable zeroes the section table fields of an ELF64 header, which is what a tool that
// strips section headers leaves behind.
func withoutSectionTable(img []byte) []byte {
	out := bytes.Clone(img)
	le := binary.LittleEndian
	le.PutUint64(out[0x28:], 0) // e_shoff
	le.PutUint16(out[0x3a:], 0) // e_shentsize
	le.PutUint16(out[0x3c:], 0) // e_shnum
	le.PutUint16(out[0x3e:], 0) // e_shstrndx
	return out
}

// elfWithWritableSegment builds a minimal ELF64 with a writable PT_LOAD segment of dataSize zero bytes
// behind a .data section, which is what debug/buildinfo searches when no .go.buildinfo section exists.
// With buildInfoSection set an empty .go.buildinfo section is added too, so the name is present without
// the magic.
func elfWithWritableSegment(t *testing.T, dataSize int, buildInfoSection bool) []byte {
	t.Helper()

	names := []byte("\x00.shstrtab\x00.data\x00.go.buildinfo\x00")
	nameOf := func(s string) uint32 {
		i := bytes.Index(names, []byte("\x00"+s+"\x00"))
		require.GreaterOrEqual(t, i, 0)
		return uint32(i + 1)
	}

	const dataAddr = 0x400000
	ehsize := uint64(binary.Size(elf.Header64{}))
	phentsize := uint64(binary.Size(elf.Prog64{}))
	shentsize := uint64(binary.Size(elf.Section64{}))
	shnum := uint64(3)
	if buildInfoSection {
		shnum++
	}
	phoff := ehsize
	shoff := phoff + phentsize
	namesOff := shoff + shnum*shentsize
	dataOff := namesOff + uint64(len(names))

	var ident [16]byte
	copy(ident[:], elf.ELFMAG)
	ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)

	buf := &bytes.Buffer{}
	write := func(v any) {
		require.NoError(t, binary.Write(buf, binary.LittleEndian, v))
	}
	write(elf.Header64{
		Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64),
		Version: uint32(elf.EV_CURRENT), Phoff: phoff, Shoff: shoff, Ehsize: uint16(ehsize),
		Phentsize: uint16(phentsize), Phnum: 1,
		Shentsize: uint16(shentsize), Shnum: uint16(shnum), Shstrndx: 1,
	})
	write(elf.Prog64{
		Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_W), Off: dataOff, Vaddr: dataAddr,
		Paddr: dataAddr, Filesz: uint64(dataSize), Memsz: uint64(dataSize), Align: 1,
	})
	write(elf.Section64{}) // the null section
	write(elf.Section64{Name: nameOf(".shstrtab"), Type: uint32(elf.SHT_STRTAB), Off: namesOff, Size: uint64(len(names)), Addralign: 1})
	write(elf.Section64{
		Name: nameOf(".data"), Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE),
		Addr: dataAddr, Off: dataOff, Size: uint64(dataSize), Addralign: 1,
	})
	if buildInfoSection {
		write(elf.Section64{
			Name: nameOf(".go.buildinfo"), Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE),
			Addr: dataAddr, Off: dataOff, Size: 0, Addralign: 1,
		})
	}
	buf.Write(names)
	buf.Write(make([]byte, dataSize))
	return buf.Bytes()
}

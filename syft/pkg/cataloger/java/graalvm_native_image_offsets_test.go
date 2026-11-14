package java

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

func TestSymbolOffset(t *testing.T) {
	tests := []struct {
		name        string
		addr        uint64
		sectionBase uint64
		wantOffset  uint64
		wantErr     bool
	}{
		{
			name:        "addr below section base underflows if unchecked, so it must error instead",
			addr:        0x900,
			sectionBase: 0x1000,
			wantErr:     true,
		},
		{
			name:        "addr equal to section base gives offset zero",
			addr:        0x1000,
			sectionBase: 0x1000,
			wantOffset:  0,
		},
		{
			name:        "addr above section base gives the exact delta",
			addr:        0x1010,
			sectionBase: 0x1000,
			wantOffset:  0x10,
		},
		{
			name:        "zero section base succeeds for any addr",
			addr:        0x2a,
			sectionBase: 0,
			wantOffset:  0x2a,
		},
		{
			name:        "max addr and max section base are equal, so offset is zero",
			addr:        math.MaxUint64,
			sectionBase: math.MaxUint64,
			wantOffset:  0,
		},
		{
			name:        "max addr against a zero section base gives the max delta",
			addr:        math.MaxUint64,
			sectionBase: 0,
			wantOffset:  math.MaxUint64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := symbolOffset(tt.addr, tt.sectionBase)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantOffset, got)
		})
	}
}

// readerFromFixture opens a testdata fixture and wraps it the same way processLocation does before
// handing it to fetchPkgs.
func readerFromFixture(t *testing.T, path string) unionreader.UnionReader {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	reader, err := unionreader.GetUnionReader(io.NopCloser(f))
	require.NoError(t, err)
	return reader
}

// neither fixture is a native image, so both exercise the path where a format matches and its fetchPkgs
// then fails, which the break at the end of the format loop makes final.
//
// the break itself cannot be distinguished from the old fall-through here: ELF, Mach-O and PE magics are
// mutually exclusive, so no fixture can validly parse as two formats. Nothing reaches the branch that
// attaches location to each package either, since no committed fixture is a real native image with an
// embedded SBOM.
func TestFetchPkgs(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{
			name:    "real native image without SBOM symbols",
			fixture: "testdata/java-builds/packages/example-java-app",
		},
		{
			name:    "real Mach-O that is not a native image",
			fixture: "testdata/java-builds/packages/gcc-amd64-darwin-exec-debug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := readerFromFixture(t, tt.fixture)
			location := file.NewLocation(tt.fixture)

			require.NotPanics(t, func() {
				gotPkgs, gotRels := fetchPkgs(reader, location)
				assert.Empty(t, gotPkgs)
				assert.Empty(t, gotRels)
			})
		})
	}
}

// covers macho.NewFile failing with something other than *macho.FormatError. Garbage bytes take the
// FormatError branch and return (nil, nil); a valid magic with nothing behind it does not.
func TestNewMachO_TruncatedFileIsARealFailure(t *testing.T) {
	// a valid Mach-O magic with nothing behind it yields io.ErrUnexpectedEOF, not a *macho.FormatError
	_, err := newMachO("truncated", bytes.NewReader([]byte{0xcf, 0xfa, 0xed, 0xfe}))
	require.ErrorContains(t, err, "unable to read executable")
}

func TestFetchPkgs_GarbageBytesYieldsNothing(t *testing.T) {
	// bytes that match none of ELF, Mach-O or PE magic numbers
	garbage := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 256)
	reader, err := unionreader.GetUnionReader(io.NopCloser(bytes.NewReader(garbage)))
	require.NoError(t, err)

	location := file.NewLocation("garbage.bin")
	require.NotPanics(t, func() {
		pkgs, rels := fetchPkgs(reader, location)
		assert.Empty(t, pkgs)
		assert.Empty(t, rels)
	})
}

func TestNewElf_SvmHeapPreFilter(t *testing.T) {
	t.Run("plain ELF without .svm_heap", func(t *testing.T) {
		ni, err := newElf("plain.elf", bytes.NewReader(minimalELF64(t, nil)))
		require.NoError(t, err)
		assert.Nil(t, ni)
	})

	t.Run("ELF with .svm_heap passes the pre-filter", func(t *testing.T) {
		ni, err := newElf("native-image.elf", bytes.NewReader(minimalELF64(t, []string{".svm_heap"})))
		require.NoError(t, err)
		require.IsType(t, nativeImageElf{}, ni)

		_, _, err = ni.fetchPkgs()
		require.EqualError(t, err, "could not retrieve symbols from binary: SHT_SYMTAB error: no symbol section, SHT_DYNSYM error: no symbol section")
	})

	t.Run("svm_heap without dot is skipped", func(t *testing.T) {
		ni, err := newElf("wrong-section.elf", bytes.NewReader(minimalELF64(t, []string{"svm_heap"})))
		require.NoError(t, err)
		assert.Nil(t, ni)
	})
}

func TestNewElf_SymbolTableReads(t *testing.T) {
	for _, symType := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		t.Run(symType.String(), func(t *testing.T) {
			for _, tt := range []struct {
				name    string
				size    uint64
				hasHeap bool
			}{
				{name: "no heap skips symbols", size: elf.Sym64Size},
				{name: "no heap skips oversized declaration", size: 1 << 40},
				{name: "heap preserves symbol loading", size: elf.Sym64Size, hasHeap: true},
			} {
				t.Run(tt.name, func(t *testing.T) {
					symbolName := ".symtab"
					if symType == elf.SHT_DYNSYM {
						symbolName = ".dynsym"
					}
					sections := []string{symbolName}
					if tt.hasHeap {
						sections = append(sections, ".svm_heap")
					}
					data := minimalELF64(t, sections)
					var header elf.Header64
					require.NoError(t, binary.Read(bytes.NewReader(data), binary.LittleEndian, &header))

					// Skip the null and .shstrtab headers.
					symbolHeaderOffset := header.Shoff + 2*uint64(header.Shentsize)
					var section elf.Section64
					require.NoError(t, binary.Read(bytes.NewReader(data[symbolHeaderOffset:]), binary.LittleEndian, &section))
					section.Type = uint32(symType)
					section.Flags = 0
					section.Off = uint64(len(data))
					section.Size = tt.size
					section.Link = 1 // .shstrtab
					section.Entsize = elf.Sym64Size
					var encoded bytes.Buffer
					require.NoError(t, binary.Write(&encoded, binary.LittleEndian, &section))
					copy(data[symbolHeaderOffset:], encoded.Bytes())

					r := &nativeImageSymbolReadTracker{
						ReaderAt:     bytes.NewReader(data),
						symbolOffset: int64(section.Off),
					}
					ni, err := newElf("symbols.elf", r)
					require.NoError(t, err)
					assert.Zero(t, r.symbolReads)
					if !tt.hasHeap {
						require.Nil(t, ni)
						return
					}
					require.NotNil(t, ni)
					_, _, err = ni.fetchPkgs()
					require.ErrorContains(t, err, "cannot load symbol section: unexpected EOF")
					assert.Positive(t, r.symbolReads)
				})
			}
		})
	}
}

type nativeImageSymbolReadTracker struct {
	io.ReaderAt
	symbolOffset int64
	symbolReads  int
}

func (r *nativeImageSymbolReadTracker) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.symbolOffset {
		r.symbolReads++
		return 0, io.ErrUnexpectedEOF
	}
	return r.ReaderAt.ReadAt(p, off)
}

// minimalELF64 builds an ELF64 with empty PROGBITS sections.
func minimalELF64(t *testing.T, extraSections []string) []byte {
	t.Helper()

	order := binary.LittleEndian

	type sectionSpec struct {
		name   string
		shType elf.SectionType
		flags  elf.SectionFlag
	}
	sections := []sectionSpec{
		{"", elf.SHT_NULL, 0},
		{".shstrtab", elf.SHT_STRTAB, 0},
	}
	for _, n := range extraSections {
		sections = append(sections, sectionSpec{n, elf.SHT_PROGBITS, elf.SHF_ALLOC})
	}

	var strtab bytes.Buffer
	strtab.WriteByte(0)
	nameOffsets := make([]uint32, len(sections))
	for i, s := range sections[1:] {
		nameOffsets[i+1] = uint32(strtab.Len())
		strtab.WriteString(s.name)
		strtab.WriteByte(0)
	}
	strtabBytes := strtab.Bytes()

	const elfHeaderSize = 64
	const sectionHeaderSize = 64

	shstrtabOffset := uint64(elfHeaderSize)
	shstrtabSize := uint64(len(strtabBytes))
	shtOffset := shstrtabOffset + shstrtabSize
	if shtOffset%8 != 0 {
		shtOffset += 8 - shtOffset%8
	}

	var buf bytes.Buffer
	var ehdr elf.Header64
	copy(ehdr.Ident[:], elf.ELFMAG)
	ehdr.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ehdr.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ehdr.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	ehdr.Ident[elf.EI_OSABI] = byte(elf.ELFOSABI_NONE)
	ehdr.Type = uint16(elf.ET_EXEC)
	ehdr.Machine = uint16(elf.EM_X86_64)
	ehdr.Version = uint32(elf.EV_CURRENT)
	ehdr.Shoff = shtOffset
	ehdr.Ehsize = elfHeaderSize
	ehdr.Shentsize = sectionHeaderSize
	ehdr.Shnum = uint16(len(sections))
	ehdr.Shstrndx = 1
	require.NoError(t, binary.Write(&buf, order, &ehdr))

	buf.Write(strtabBytes)
	for uint64(buf.Len()) < shtOffset {
		buf.WriteByte(0)
	}

	for i, s := range sections {
		var shdr elf.Section64
		shdr.Name = nameOffsets[i]
		shdr.Type = uint32(s.shType)
		shdr.Flags = uint64(s.flags)
		if s.shType == elf.SHT_STRTAB {
			shdr.Off = shstrtabOffset
			shdr.Size = shstrtabSize
		}
		require.NoError(t, binary.Write(&buf, order, &shdr))
	}

	return buf.Bytes()
}

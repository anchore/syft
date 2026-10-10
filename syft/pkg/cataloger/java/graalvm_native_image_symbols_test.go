package java

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/testutils"
)

// the native image under test is synthesized rather than built: a GraalVM toolchain is heavy to pull in,
// and all fetchPkgs needs from the ELF is a .data section holding the compressed SBOM and symbol tables
// that name where in it the SBOM and its length live.
const (
	testNativeImageDataAddr = 0x400000
	testNativeImageSbomPath = "testdata/graalvm-sbom/micronaut.json"
)

var testNativeImageSbomPackages = []string{"netty-codec-http2", "core", "basic-lib", "main-test-app"}

func TestNativeImageElf_SbomSymbolsInSymtab(t *testing.T) {
	data, names := nativeImageDataAndSymbols(t)
	img := buildNativeImageELF(t, data, symbolTables{
		symtab: nativeImageSymtab(t, names, 0),
	})
	assertNativeImagePackages(t, img)
}

func TestNativeImageElf_SbomSymbolsInDynsymOnly(t *testing.T) {
	// a native image whose static symbol table was stripped still exports the symbols dynamically, and
	// getSymbols reads .dynsym alongside .symtab; the string-table check has to look in .dynstr too
	data, names := nativeImageDataAndSymbols(t)
	img := buildNativeImageELF(t, data, symbolTables{
		dynsym: nativeImageSymtab(t, names, 0),
	})
	assertNativeImagePackages(t, img)
}

func TestNativeImageElf_SbomSymbolsAsTailsOfLongerNames(t *testing.T) {
	// linkers may store a short name as the tail of a longer one in the string table, so "sbom" can live
	// at offset n+1 of "xsbom" with no NUL in front of it. The check must not demand one.
	data, names := nativeImageDataAndSymbols(t)
	img := buildNativeImageELF(t, data, symbolTables{
		symtab: nativeImageSymtabTailMerged(t, names),
	})
	assertNativeImagePackages(t, img)
}

func TestNativeImageElf_SbomSymbolsPastTheFirstScanChunk(t *testing.T) {
	// the scan reads the string table in fixed chunks; the names here sit well past the first one, and
	// the first of them lands on a chunk boundary. TestNameScanner_FindsNamesAcrossChunkBoundaries
	// walks every offset around the boundaries; this proves the whole path on top of it.
	data, names := nativeImageDataAndSymbols(t)
	img := buildNativeImageELF(t, data, symbolTables{
		symtab: nativeImageSymtab(t, names, nativeImageStringTableChunk+16),
	})
	assertNativeImagePackages(t, img)
}

func TestNativeImageElf_SkipsSymbolLoadWhenNamesAreAbsent(t *testing.T) {
	// a large, ordinary symbol table: what nearly every ELF executable in an image looks like to this
	// cataloger. None of the SBOM symbols are present, so the symbols must never be materialized.
	const symbols = 20000
	syms, strs := manySymbols(t, symbols, nil)
	img := buildNativeImageELF(t, []byte("not an sbom"), symbolTables{symtab: symbolTable{syms: syms, strs: strs}})

	ni := nativeImageELF(t, img)
	require.False(t, ni.mayHoldSbomSymbols())

	var err error
	gated := testutils.MeasureAlloc(t, func() {
		_, _, err = ni.fetchPkgs()
	})
	require.EqualError(t, err, nativeImageMissingSymbolsError)

	// the path this guards: what loading the symbols of the same binary costs
	loaded := testutils.MeasureAlloc(t, func() {
		si, err := ni.getSymbols()
		require.NoError(t, err)
		require.Len(t, si, symbols)
	})
	t.Logf("fetchPkgs allocated %d bytes, getSymbols %d bytes, symbol table %d bytes, string table %d bytes",
		gated, loaded, len(syms), len(strs))
	assert.Less(t, gated, uint64(len(syms)), "the gated path should not allocate even the raw symbol table")
	assert.Less(t, gated*4, loaded, "the gated path should cost a small fraction of loading the symbols")
}

func TestNativeImageElf_AllThreeSymbolsRequired(t *testing.T) {
	// two of the three names present is still a binary with no SBOM, and the error is the same one the
	// symbol scan would have reached
	for _, missing := range nativeImageSbomSymbolNames {
		t.Run("missing "+missing, func(t *testing.T) {
			var present []string
			for _, name := range nativeImageSbomSymbolNames {
				if name != missing {
					present = append(present, name)
				}
			}
			syms, strs := manySymbols(t, 100, present)
			ni := nativeImageELF(t, buildNativeImageELF(t, []byte("data"), symbolTables{symtab: symbolTable{syms: syms, strs: strs}}))
			assert.False(t, ni.mayHoldSbomSymbols())
			_, _, err := ni.fetchPkgs()
			require.EqualError(t, err, nativeImageMissingSymbolsError)
		})
	}
}

func TestNativeImageElf_NoSymbolTablesTakesTheOriginalPath(t *testing.T) {
	// nothing to scan: the check stands aside and getSymbols reports the file the way it always did
	ni := nativeImageELF(t, buildNativeImageELF(t, []byte("data"), symbolTables{}))
	assert.True(t, ni.mayHoldSbomSymbols())
	_, _, err := ni.fetchPkgs()
	require.ErrorContains(t, err, "could not retrieve symbols from binary")
}

func TestNameScanner_FindsNamesAcrossChunkBoundaries(t *testing.T) {
	// every offset in a band around the first three chunk boundaries, so a name is placed on both sides
	// of each one and at every split in between, plus the ends of the table. One scanner is reused across
	// the tables of a binary, so the same one is reused here too, to show a scan leaves nothing behind
	names := []string{"sbom", "sbom_length", "__svm_version_info"}
	var offsets []int
	for boundary := 1; boundary <= 3; boundary++ {
		for delta := -40; delta <= 40; delta++ {
			offsets = append(offsets, boundary*nativeImageStringTableChunk+delta)
		}
	}
	scanner := newNameScanner(names, nativeImageStringTableChunk)
	for _, name := range names {
		for _, tail := range []int{0, 1, 17} {
			// at the very start, and ending flush with the end of the table
			for _, offset := range append(offsets, 0, 1) {
				table := make([]byte, offset+len(name)+1+tail)
				copy(table[offset:], name+"\x00")
				found := map[string]bool{}
				require.NoError(t, scanner.scan(bytes.NewReader(table), found))
				assert.Equal(t, map[string]bool{name: true}, found, "name %q at offset %d with %d trailing bytes", name, offset, tail)
			}
		}
	}
}

func TestNameScanner_RequiresTheTerminator(t *testing.T) {
	// a symbol's name runs to the next NUL, so "sbom" immediately followed by other bytes is some other
	// symbol's name (or an unterminated table debug/elf resolves to "")
	found := map[string]bool{}
	require.NoError(t, newNameScanner([]string{"sbom", "sbom_length"}, nativeImageStringTableChunk).scan(bytes.NewReader([]byte("\x00sbomx\x00sbom_lengthy\x00sbom")), found))
	assert.Empty(t, found)
}

// nativeImageDataAndSymbols lays out a .data section the way a native image does, the compressed SBOM
// followed by its 8-byte length, and the symbols that point into it.
func nativeImageDataAndSymbols(t *testing.T) ([]byte, []namedSymbol) {
	t.Helper()
	data, sbomLength := createCompressedSbom(t, testNativeImageSbomPath)
	return data, []namedSymbol{
		{name: nativeImageSbomSymbol, value: testNativeImageDataAddr},
		{name: nativeImageSbomLengthSymbol, value: testNativeImageDataAddr + sbomLength},
		{name: nativeImageSbomVersionSymbol, value: testNativeImageDataAddr + 1},
	}
}

func assertNativeImagePackages(t *testing.T, img []byte) {
	t.Helper()
	ni := nativeImageELF(t, img)
	require.True(t, ni.mayHoldSbomSymbols())
	pkgs, _, err := ni.fetchPkgs()
	require.NoError(t, err)
	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name)
	}
	assert.ElementsMatch(t, testNativeImageSbomPackages, names)
}

func nativeImageELF(t *testing.T, img []byte) nativeImageElf {
	t.Helper()
	ni, err := newElf("synthetic-native-image", bytes.NewReader(img))
	require.NoError(t, err)
	require.NotNil(t, ni)
	return ni.(nativeImageElf)
}

type namedSymbol struct {
	name  string
	value uint64
}

type symbolTable struct {
	syms []byte // Sym64 entries, the null entry first
	strs []byte // the string table they index
}

type symbolTables struct {
	symtab symbolTable // emitted as .symtab/.strtab when non-empty
	dynsym symbolTable // emitted as .dynsym/.dynstr when non-empty
}

// nativeImageSymtab writes the symbols with their names laid out one after another in the string table,
// after `padding` bytes of filler.
func nativeImageSymtab(t *testing.T, symbols []namedSymbol, padding int) symbolTable {
	t.Helper()
	strs := []byte{0}
	strs = append(strs, bytes.Repeat([]byte{'p'}, padding)...)
	if padding > 0 {
		strs = append(strs, 0)
	}
	var syms bytes.Buffer
	writeSym(t, &syms, elf.Sym64{})
	for _, s := range symbols {
		off := uint32(len(strs))
		strs = append(strs, s.name...)
		strs = append(strs, 0)
		writeSym(t, &syms, elf.Sym64{Name: off, Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT), Shndx: 2, Value: s.value, Size: 8})
	}
	return symbolTable{syms: syms.Bytes(), strs: strs}
}

// nativeImageSymtabTailMerged stores every name as the tail of a longer one, so no SBOM symbol name is
// preceded by a NUL in the string table.
func nativeImageSymtabTailMerged(t *testing.T, symbols []namedSymbol) symbolTable {
	t.Helper()
	strs := []byte{0}
	var syms bytes.Buffer
	writeSym(t, &syms, elf.Sym64{})
	for _, s := range symbols {
		strs = append(strs, "prefix_"...)
		off := uint32(len(strs))
		strs = append(strs, s.name...)
		strs = append(strs, 0)
		writeSym(t, &syms, elf.Sym64{Name: off, Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT), Shndx: 2, Value: s.value, Size: 8})
	}
	return symbolTable{syms: syms.Bytes(), strs: strs}
}

// manySymbols writes n generated symbols plus the given extra names, none pointing anywhere useful.
func manySymbols(t *testing.T, n int, extra []string) ([]byte, []byte) {
	t.Helper()
	strs := []byte{0}
	var syms bytes.Buffer
	writeSym(t, &syms, elf.Sym64{})
	add := func(name string) {
		off := uint32(len(strs))
		strs = append(strs, name...)
		strs = append(strs, 0)
		writeSym(t, &syms, elf.Sym64{Name: off, Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), Shndx: 2, Value: uint64(0x1000 + off), Size: 4})
	}
	for i := 0; i < n; i++ {
		add(fmt.Sprintf("_ZN7example6module%dfunction%dEv", i%97, i))
	}
	for _, name := range extra {
		add(name)
	}
	return syms.Bytes(), strs
}

func writeSym(t *testing.T, w *bytes.Buffer, sym elf.Sym64) {
	t.Helper()
	require.NoError(t, binary.Write(w, binary.LittleEndian, sym))
}

// buildNativeImageELF builds a minimal ELF64 with a .data section at testNativeImageDataAddr and whichever
// symbol tables are given. Section indices: 0 null, 1 .shstrtab, 2 .data, then the tables in pairs.
func buildNativeImageELF(t *testing.T, data []byte, tables symbolTables) []byte {
	t.Helper()

	type section struct {
		name    string
		typ     elf.SectionType
		flags   elf.SectionFlag
		addr    uint64
		link    uint32
		entsize uint64
		data    []byte
	}
	sections := []section{
		{name: ".data", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, addr: testNativeImageDataAddr, data: data},
	}
	addTable := func(symName, strName string, typ elf.SectionType, tbl symbolTable) {
		if len(tbl.syms) == 0 {
			return
		}
		symIndex := uint32(len(sections) + 2)
		sections = append(sections,
			section{name: symName, typ: typ, link: symIndex + 1, entsize: elf.Sym64Size, data: tbl.syms},
			section{name: strName, typ: elf.SHT_STRTAB, data: tbl.strs},
		)
	}
	addTable(".symtab", ".strtab", elf.SHT_SYMTAB, tables.symtab)
	addTable(".dynsym", ".dynstr", elf.SHT_DYNSYM, tables.dynsym)

	names := []byte("\x00.shstrtab\x00")
	nameOffsets := make([]uint32, len(sections))
	for i, s := range sections {
		nameOffsets[i] = uint32(len(names))
		names = append(names, s.name...)
		names = append(names, 0)
	}

	ehsize := uint64(binary.Size(elf.Header64{}))
	shentsize := uint64(binary.Size(elf.Section64{}))
	shnum := uint64(len(sections) + 2)
	shoff := ehsize
	bodyOff := shoff + shnum*shentsize

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
		Version: uint32(elf.EV_CURRENT), Shoff: shoff, Ehsize: uint16(ehsize),
		Shentsize: uint16(shentsize), Shnum: uint16(shnum), Shstrndx: 1,
	})
	write(elf.Section64{}) // the null section
	write(elf.Section64{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: bodyOff, Size: uint64(len(names)), Addralign: 1})
	off := bodyOff + uint64(len(names))
	for i, s := range sections {
		write(elf.Section64{
			Name: nameOffsets[i], Type: uint32(s.typ), Flags: uint64(s.flags), Addr: s.addr,
			Off: off, Size: uint64(len(s.data)), Link: s.link, Entsize: s.entsize, Addralign: 1,
		})
		off += uint64(len(s.data))
	}
	buf.Write(names)
	for _, s := range sections {
		buf.Write(s.data)
	}
	return buf.Bytes()
}

/*
Package elfutil provides an ELF opener that rejects sections whose compression headers declare an
implausible decompressed size.

debug/elf sizes a section's buffer from the section's own compression header, and a highly compressible
stream really does deliver the bytes that header promises, so internal/saferio's chunked read does not
help: it appends its way to every declared byte, and Go's 1.25x slice growth puts the lifetime cost near
five times that. 512MB of zeros is 510KB of zlib, and that file drives elf.NewFile through 2.6GB of
allocation and returns no error, which is a fatal Go OOM rather than a recoverable panic. Zlib caps out
near 1000:1, but debug/elf also accepts zstd, which passes 32000:1 on zeroed input, so the input needed
to declare a given size is smaller still.

The check runs in two parts, because debug/elf expands sections at two different times:

  - the section-name string table is the one section elf.NewFile expands on its own, so it has to be
    bounded against the raw bytes before the call is made. That is CheckSectionNameTable, and the walk
    of the section table it needs is why this package decodes any ELF structures by hand at all.
  - every other section is expanded lazily by (*Section).Open, so those are bounded after the parse,
    where names, types and decompressed sizes are resolved already.

Only the sections syft can actually drive debug/elf into decompressing are bounded. DWARF is deliberately
excluded: syft never asks for it, so a binary carrying a large compressed .debug_info is cataloged rather
than skipped over a section nobody reads.

Sources:
  - https://www.sco.com/developers/gabi/latest/ch4.sheader.html
  - https://groups.google.com/g/generic-abi/c/satyPkuMisk
  - https://docs.oracle.com/en/operating-systems/solaris/oracle-solaris/11.4/linkers-libraries/gnu-style-section-compression.html
  - https://sourceware.org/pipermail/binutils/2015-July/089559.html
  - https://cs.opensource.google/go/go/+/refs/tags/go1.26.5:src/debug/elf/file.go
  - https://go.dev/doc/go1.19#linker
*/
package elfutil

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"

	intFile "github.com/anchore/syft/internal/file"
)

// maxDeclaredSectionSize bounds the decompressed size any single reachable section may declare.
//
// The bound only ever applies to a compressed section, and the gABI allows compression only on
// non-allocable ones, so nothing syft reads on the hot path (.data, .text, notes) can reach it. The
// realistic worst case is a compressed .symtab/.strtab on a very large binary, well under this. The
// trade-off is that a binary whose symbol or string table decompresses past this is skipped rather than
// cataloged; that is the correct direction to fail, since the alternative is OOM-killing the whole scan.
//
// Note that this is a per-section bound, not a per-file one: a file may hold several sections that each
// sit just under it. That is deliberate, since the sections syft actually reads are few.
const maxDeclaredSectionSize uint64 = 128 * intFile.MB

// legacyZlibHeaderSize is the size of the .zdebug header: the "ZLIB" magic plus a big-endian size.
const legacyZlibHeaderSize = 12

// sectionsReadByName are the sections syft asks debug/elf for by name. Everything else it reaches by
// section type, which reachableSections covers separately. Not every one of these ends in a read of the
// contents (.text is used for its address, .symtab only for a nil check), but bounding any name syft asks
// for is cheaper to keep true than tracking which lookups reach Data.
//
// Add to this list when a cataloger starts reading a new section by name. The ruleguard rule only stops a
// new debug/elf call site; it cannot see a new (*Section).Data call behind an already-bounded open.
var sectionsReadByName = map[string]struct{}{
	".symtab":       {},
	".data":         {},
	".text":         {},
	".gopclntab":    {},
	".note.package": {},
	".modinfo":      {},
}

// wire sizes of the structures we decode, which differ between the two ELF classes
var (
	sizeSection32 = int64(binary.Size(elf.Section32{}))
	sizeSection64 = int64(binary.Size(elf.Section64{}))
	sizeChdr32    = int64(binary.Size(elf.Chdr32{}))
	sizeChdr64    = int64(binary.Size(elf.Chdr64{}))
)

// NewFile parses an ELF file, rejecting it if a section syft may read declares a decompressed size this
// process should not be asked to allocate. It is a drop-in for elf.NewFile, except that a rejection is
// reported as a plain error rather than an *elf.FormatError, so callers that distinguish "not an ELF"
// from "bad ELF" treat it as the latter.
func NewFile(r io.ReaderAt) (*elf.File, error) {
	if err := CheckSectionNameTable(r); err != nil {
		return nil, err
	}

	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	if err := checkReachableSections(f); err != nil {
		return nil, err
	}
	return f, nil
}

// checkReachableSections bounds every section syft can drive debug/elf into decompressing. This runs
// after the parse because (*Section).Open expands lazily, so nothing has been allocated yet.
func checkReachableSections(f *elf.File) error {
	for i := range reachableSections(f) {
		s := f.Sections[i]
		declared, claimed := declaredSectionSize(s)
		if claimed && declared > maxDeclaredSectionSize {
			return fmt.Errorf("elf section %q declares %d decompressed bytes, over the %d byte limit",
				s.Name, declared, maxDeclaredSectionSize)
		}
	}
	return nil
}

// reachableSections reports which sections syft can actually reach. It marks by type generously, since
// the debug/elf accessors all go through SectionByType, which returns only the first section of a type: a
// second SHT_SYMTAB is bounded here despite being unreachable. DWARF is absent by design: nothing in syft
// calls File.DWARF, so debug/elf is never asked to expand a .debug_* section.
func reachableSections(f *elf.File) map[int]struct{} {
	reach := make(map[int]struct{})
	mark := func(i int) {
		if i >= 0 && i < len(f.Sections) {
			reach[i] = struct{}{}
		}
	}
	for i, s := range f.Sections {
		switch s.Type {
		case elf.SHT_SYMTAB, elf.SHT_DYNSYM, elf.SHT_DYNAMIC:
			// File.Symbols, File.DynamicSymbols and File.DynString each read one of these plus the
			// string table its Link field points at
			mark(i)
			mark(int(s.Link))
		case elf.SHT_GNU_VERSYM, elf.SHT_GNU_VERDEF, elf.SHT_GNU_VERNEED:
			// File.DynamicSymbols pulls the symbol version tables in behind the caller's back, via
			// gnuVersionInit. Strictly they are only reachable alongside a .dynsym, and VERDEF/VERNEED
			// only alongside a VERSYM, but they are marked unconditionally rather than tracked: the only
			// file that loses out carries an oversized version table and no dynamic symbols at all,
			// which is not something a toolchain emits.
			mark(i)
		}
		if _, ok := sectionsReadByName[s.Name]; ok {
			mark(i)
		}
	}
	return reach
}

// declaredSectionSize reports the decompressed size a section claims, if it claims one at all.
//
// ELF grew two separate ways of saying "this section is compressed", and (*Section).Open honors both, so
// this dispatches the same way Open does and in the same order. That correspondence is the whole design:
// wherever Open returns a decompressing reader, this reports the size that reader will expand to. Missing
// one is the bug this package exists to prevent, so when a Go release changes Open, this is what has to be
// re-read against it.
//
// It deliberately over-reports in one place, an unrecognized ch_type: Open hands back an error reader for
// anything but zlib and zstd, so nothing is allocated, but the type is not exposed on elf.Section and
// re-reading the header for it would only spare a file debug/elf cannot decompress anyway.
func declaredSectionSize(s *elf.Section) (uint64, bool) {
	// SHT_NOBITS marks a section that occupies no bytes in the file, .bss being the familiar one: it
	// declares a size the loader zero-fills at run time rather than a size stored anywhere. Its sh_offset
	// is only a conceptual placement and routinely lands inside some other section's bytes. Two things
	// follow, and both say to test this before looking at compression at all:
	//   - Open tests it first too, ahead of any compression, and hands back a reader that fails every
	//     read. Nothing is allocated for the declared size, however large it is.
	//   - the gABI forbids SHF_COMPRESSED here, but elf.NewFile does not enforce that and parses a
	//     compression header anyway. The Size it leaves on the section was decoded from whatever bytes lie
	//     at that borrowed offset, so it is not a figure to bound anything against.
	if s.Type == elf.SHT_NOBITS {
		return 0, false
	}

	if s.Flags&elf.SHF_COMPRESSED != 0 {
		return chdrDeclaredSize(s)
	}
	return zdebugDeclaredSize(s)
}

// chdrDeclaredSize reports the size declared by the modern compression form: an SHF_COMPRESSED flag,
// plus an Elf32_Chdr or Elf64_Chdr at the head of the section giving the algorithm and the decompressed
// size. This is the form standardized in the gABI and the one any current toolchain emits.
func chdrDeclaredSize(s *elf.Section) (uint64, bool) {
	// SHF_ALLOC marks a section the loader maps into the running process, and nothing decompresses a
	// section on its way into memory, so the gABI makes the two flags mutually exclusive. Open enforces
	// that rather than tolerating it: a section setting both gets an error reader, never a decompressing
	// one, so a size declared alongside SHF_ALLOC is never allocated.
	if s.Flags&elf.SHF_ALLOC != 0 {
		return 0, false
	}
	// elf.NewFile decodes the Chdr during the parse and overwrites Size with ch_size, leaving the on-disk
	// figure in FileSize. So the number a hostile file controls is already here, and no second read of the
	// file is needed.
	return s.Size, true
}

// zdebugDeclaredSize reports the size declared by the legacy compression form. Before SHF_COMPRESSED was
// added to the gABI, GNU tooling signaled a compressed debug section by renaming it, .debug_info to
// .zdebug_info, and prefixing the payload with a header of its own: the magic "ZLIB" followed by the
// decompressed size. Toolchains default to the gABI form now, Go's own linker having emitted .zdebug up
// to 1.19, but this is not vestigial: nothing ties the prefix to a debug section, so a crafted file can
// hang it on a section syft does read, an SHT_SYMTAB named .zdebug_x being the obvious one.
func zdebugDeclaredSize(s *elf.Section) (uint64, bool) {
	// no flag distinguishes this form, so the section name is the only signal, and Open gates on the name
	// before it so much as looks at the bytes. Matching that gate exactly is what keeps an ordinary
	// section whose contents happen to begin with "ZLIB" out of scope: Open will never decompress it, so
	// neither may this.
	if !strings.HasPrefix(s.Name, ".zdebug") {
		return 0, false
	}
	// unlike the Chdr above, nothing in the parse has looked at this header, so read it here. Reading off
	// the section is only safe because SHF_COMPRESSED is clear on this path, since elf.NewFile leaves the
	// embedded ReaderAt nil for a compressed one. Open treats a short read or absent magic as "not really
	// compressed after all" and serves the bytes as they lie.
	var hdr [legacyZlibHeaderSize]byte
	if n, _ := s.ReadAt(hdr[:], 0); n != legacyZlibHeaderSize || string(hdr[:4]) != "ZLIB" {
		return 0, false
	}
	// the size is big-endian whatever byte order the rest of the file uses. The header predates the gABI
	// mechanism and was simply defined that way, carrying no endianness of its own.
	return binary.BigEndian.Uint64(hdr[4:]), true
}

// CheckSectionNameTable bounds the one section elf.NewFile expands on its own. Anything it cannot walk is
// passed through untouched, leaving elf.NewFile to describe the file. It does not repeat every check
// elf.NewFile makes ahead of that expansion, though, so a file that is both malformed and oversized can
// come back with this error rather than an *elf.FormatError.
//
// NewFile calls this itself. It is exported for the callers that cannot use NewFile because the
// debug/elf call is made for them inside another package, debug/buildinfo being the one syft reaches:
// gate the reader on this and the eager section-name table read is bounded, which is everything that
// package expands today, since it reaches .go.buildinfo through the program headers instead.
func CheckSectionNameTable(r io.ReaderAt) error {
	class, order, ok := identify(r)
	if !ok {
		return nil
	}
	sh, ok := sectionNameTableHeader(r, class, order)
	if !ok {
		return nil
	}
	// the name table's own name is not resolved at the point elf.NewFile reads it, so debug/elf cannot
	// take the legacy .zdebug path for this section: only a compression header can apply
	if sh.flags&uint64(elf.SHF_COMPRESSED) == 0 {
		return nil
	}
	declared, err := compressedSize(r, class, order, sh.offset)
	if err != nil {
		return nil //nolint:nilerr // truncated section; elf.NewFile will say so
	}
	if declared > maxDeclaredSectionSize {
		return fmt.Errorf("elf section name table declares %d decompressed bytes, over the %d byte limit",
			declared, maxDeclaredSectionSize)
	}
	return nil
}

// identify decodes the class and byte order every later read depends on, out of the file's 16
// identification bytes. It reports false for anything that is not an ELF this package understands, so
// elf.NewFile remains the single source of format errors.
func identify(r io.ReaderAt) (elf.Class, binary.ByteOrder, bool) {
	var ident [16]byte
	if _, err := io.ReadFull(io.NewSectionReader(r, 0, int64(len(ident))), ident[:]); err != nil {
		return 0, nil, false
	}
	if string(ident[:4]) != elf.ELFMAG {
		return 0, nil, false
	}

	class := elf.Class(ident[elf.EI_CLASS])
	if class != elf.ELFCLASS32 && class != elf.ELFCLASS64 {
		return 0, nil, false
	}

	switch elf.Data(ident[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		return class, binary.LittleEndian, true
	case elf.ELFDATA2MSB:
		return class, binary.BigEndian, true
	}
	return 0, nil, false
}

// sectionNameTableHeader locates the header of the section syft's own parse cannot reach, the one
// elf.NewFile expands for itself. It reports false whenever the file names no name table or is malformed
// enough that nothing gets decompressed: either way there is nothing to bound, and describing the file is
// elf.NewFile's job rather than this package's.
func sectionNameTableHeader(r io.ReaderAt, class elf.Class, order binary.ByteOrder) (sectionHeader, bool) {
	shoff, shentsize, shnum, shstrndx, err := fileHeader(r, class, order)
	if err != nil || shoff <= 0 || shentsize < sectionHeaderSize(class) {
		return sectionHeader{}, false
	}

	// a zero e_shnum means the real count lives in section 0's size field, and an e_shstrndx of
	// SHN_XINDEX means the real string table index lives in that same header's link field
	if shnum == 0 {
		sh, err := readSectionHeader(r, class, order, shoff)
		if err != nil {
			return sectionHeader{}, false
		}
		shnum = sh.size
		if shstrndx == uint64(elf.SHN_XINDEX) {
			shstrndx = uint64(sh.link)
		}
	}

	// an index of zero means the file has no section name table, so elf.NewFile returns before reading one.
	// An out-of-range index expands nothing either, though elf.NewFile only rejects it when e_shnum was
	// non-zero; reached through SHN_XINDEX it indexes out of range and panics instead. That is a
	// recoverable panic the task executor already contains, unlike the OOM this package exists to stop.
	if shstrndx == 0 || shstrndx >= shnum {
		return sectionHeader{}, false
	}
	// the index is file-controlled, so guard the multiply and then the sum against a table the file
	// places past the end of the address space
	if shstrndx > uint64(math.MaxInt64)/uint64(shentsize) {
		return sectionHeader{}, false
	}
	off := shoff + int64(shstrndx)*shentsize
	if off < 0 {
		return sectionHeader{}, false
	}

	sh, err := readSectionHeader(r, class, order, off)
	if err != nil {
		return sectionHeader{}, false
	}
	return sh, true
}

// sectionHeader is the handful of fields we need out of an Elf32_Shdr or an Elf64_Shdr.
type sectionHeader struct {
	flags  uint64
	offset int64
	size   uint64
	link   uint32
}

// fileHeader returns the section table location and shape out of the ELF file header.
func fileHeader(r io.ReaderAt, class elf.Class, order binary.ByteOrder) (shoff, shentsize int64, shnum, shstrndx uint64, err error) {
	if class == elf.ELFCLASS32 {
		var h elf.Header32
		if err := binary.Read(io.NewSectionReader(r, 0, int64(binary.Size(h))), order, &h); err != nil {
			return 0, 0, 0, 0, err
		}
		return int64(h.Shoff), int64(h.Shentsize), uint64(h.Shnum), uint64(h.Shstrndx), nil
	}
	var h elf.Header64
	if err := binary.Read(io.NewSectionReader(r, 0, int64(binary.Size(h))), order, &h); err != nil {
		return 0, 0, 0, 0, err
	}
	// Shoff is a uint64, so a file may claim an offset that does not fit in an int64; the caller rejects
	// a negative result rather than wrapping into a plausible-looking one
	return int64(h.Shoff), int64(h.Shentsize), uint64(h.Shnum), uint64(h.Shstrndx), nil
}

// readSectionHeader decodes one section header. Reads go through binary.Read, which uses io.ReadFull, so
// a short read is an error rather than a partially-zeroed header.
func readSectionHeader(r io.ReaderAt, class elf.Class, order binary.ByteOrder, off int64) (sectionHeader, error) {
	sr := io.NewSectionReader(r, off, sectionHeaderSize(class))
	if class == elf.ELFCLASS32 {
		var sh elf.Section32
		if err := binary.Read(sr, order, &sh); err != nil {
			return sectionHeader{}, err
		}
		return sectionHeader{
			flags:  uint64(sh.Flags),
			offset: int64(sh.Off),
			size:   uint64(sh.Size),
			link:   sh.Link,
		}, nil
	}
	var sh elf.Section64
	if err := binary.Read(sr, order, &sh); err != nil {
		return sectionHeader{}, err
	}
	return sectionHeader{
		flags:  sh.Flags,
		offset: int64(sh.Off),
		size:   sh.Size,
		link:   sh.Link,
	}, nil
}

// compressedSize reads the decompressed size out of a section's SHF_COMPRESSED header. Chdr64 carries a
// blank field that binary.Size counts and binary.Read skips, so the decoded offsets match what debug/elf
// reaches for with unsafe.Offsetof.
func compressedSize(r io.ReaderAt, class elf.Class, order binary.ByteOrder, off int64) (uint64, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative section offset")
	}
	sr := io.NewSectionReader(r, off, compressionHeaderSize(class))
	if class == elf.ELFCLASS32 {
		var ch elf.Chdr32
		if err := binary.Read(sr, order, &ch); err != nil {
			return 0, err
		}
		return uint64(ch.Size), nil
	}
	var ch elf.Chdr64
	if err := binary.Read(sr, order, &ch); err != nil {
		return 0, err
	}
	return ch.Size, nil
}

func sectionHeaderSize(class elf.Class) int64 {
	if class == elf.ELFCLASS32 {
		return sizeSection32
	}
	return sizeSection64
}

func compressionHeaderSize(class elf.Class) int64 {
	if class == elf.ELFCLASS32 {
		return sizeChdr32
	}
	return sizeChdr64
}

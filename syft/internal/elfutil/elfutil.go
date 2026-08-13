/*
Package elfutil provides an ELF opener that rejects sections whose compression headers declare an
implausible decompressed size.

debug/elf sizes a section's buffer from the section's own compression header, and a highly compressible
stream really does deliver the bytes that header promises, so internal/saferio's chunked read does not
help: it faithfully allocates every byte. A 2MB input file is enough to drive elf.NewFile to allocate over
10GB, which is a fatal Go OOM rather than a recoverable panic.

The check runs in two parts, because debug/elf expands sections at two different times. elf.NewFile
expands exactly one section on its own, the section-name string table, so that one has to be bounded
against the raw bytes before the call is made. Every other section is expanded lazily by
(*Section).Open, so those are bounded after the parse, where names, types and decompressed sizes are all
resolved already and no hand-rolled walk of the section table is needed.

Only the sections syft can actually drive debug/elf into decompressing are bounded. DWARF is deliberately
excluded: syft never asks for it, so a binary carrying a large compressed .debug_info is cataloged rather
than skipped over a section nobody reads.
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
// Only non-allocable sections can legitimately be compressed, so nothing syft reads on the hot path
// (.data, .go.buildinfo, notes) is affected at all. The realistic ceiling for a section syft does read out
// of a compressed file is .symtab/.strtab on a very large binary, orders of magnitude under this. The
// trade-off is that a binary whose symbol or string table decompresses past this is skipped rather than
// cataloged; that is the correct direction to fail, since the alternative is OOM-killing the whole scan.
//
// Note that this is a per-section bound, not a per-file one: a file may hold several sections that each
// sit just under it. That is deliberate, since the sections syft actually reads are few.
const maxDeclaredSectionSize uint64 = 128 * intFile.MB

// legacyZlibHeaderSize is the size of the .zdebug header: the "ZLIB" magic plus a big-endian size.
const legacyZlibHeaderSize = 12

// sectionsReadByName are the sections syft asks debug/elf for by name. Everything else it reaches by
// section type, which reachableSections covers separately.
var sectionsReadByName = map[string]struct{}{
	".symtab":       {},
	".data":         {},
	".text":         {},
	".gopclntab":    {},
	".note.package": {},
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
	if err := checkSectionNameTable(r); err != nil {
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
		declared, claimed := declaredSize(s)
		if claimed && declared > maxDeclaredSectionSize {
			return fmt.Errorf("elf section %q declares %d decompressed bytes, over the %d byte limit",
				s.Name, declared, maxDeclaredSectionSize)
		}
	}
	return nil
}

// reachableSections reports which sections syft can actually reach. DWARF is absent by design: nothing
// in syft calls File.DWARF, so debug/elf is never asked to expand a .debug_* section.
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
		}
		if _, ok := sectionsReadByName[s.Name]; ok {
			mark(i)
		}
	}
	return reach
}

// declaredSize reports the decompressed size a section claims, if it claims one at all.
func declaredSize(s *elf.Section) (uint64, bool) {
	// SHT_NOBITS occupies no file space, so its sh_offset addresses bytes belonging to some other
	// section. debug/elf returns a reader that never yields bytes for it and never decompresses it.
	if s.Type == elf.SHT_NOBITS {
		return 0, false
	}

	if s.Flags&elf.SHF_COMPRESSED != 0 {
		// debug/elf refuses to decompress an allocable section, so it never allocates for one
		if s.Flags&elf.SHF_ALLOC != 0 {
			return 0, false
		}
		// elf.NewFile has already resolved Size from the section's compression header
		return s.Size, true
	}

	// the legacy .zdebug form, which debug/elf honors in (*Section).Open gated on the section name. A
	// section syft reads is not normally named this way, but nothing stops a file from doing it, and the
	// name gate is matched exactly here so an ordinary section whose bytes happen to start with "ZLIB" is
	// not mistaken for a compressed one.
	if !strings.HasPrefix(s.Name, ".zdebug") {
		return 0, false
	}
	var hdr [legacyZlibHeaderSize]byte
	if n, _ := s.ReadAt(hdr[:], 0); n != legacyZlibHeaderSize || string(hdr[:4]) != "ZLIB" {
		return 0, false
	}
	// the legacy header is big-endian regardless of the file's own byte order
	return binary.BigEndian.Uint64(hdr[4:]), true
}

// checkSectionNameTable bounds the one section elf.NewFile expands on its own. Anything that does not
// parse as ELF is passed through untouched, so that elf.NewFile remains the single source of format
// errors.
func checkSectionNameTable(r io.ReaderAt) error {
	var ident [16]byte
	if _, err := io.ReadFull(io.NewSectionReader(r, 0, int64(len(ident))), ident[:]); err != nil {
		return nil //nolint:nilerr // not our error to report; let elf.NewFile describe the file
	}
	if string(ident[:4]) != elf.ELFMAG {
		return nil
	}

	class := elf.Class(ident[elf.EI_CLASS])
	if class != elf.ELFCLASS32 && class != elf.ELFCLASS64 {
		return nil
	}

	var order binary.ByteOrder
	switch elf.Data(ident[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		order = binary.LittleEndian
	case elf.ELFDATA2MSB:
		order = binary.BigEndian
	default:
		return nil
	}

	shoff, shentsize, shnum, shstrndx, err := fileHeader(r, class, order)
	if err != nil || shoff <= 0 || shentsize < sectionHeaderSize(class) {
		return nil //nolint:nilerr // malformed or has no section table; elf.NewFile will say so
	}

	// a zero e_shnum means the real count lives in section 0's size field, and an e_shstrndx of
	// SHN_XINDEX means the real string table index lives in that same header's link field
	if shnum == 0 {
		sh, err := readSectionHeader(r, class, order, shoff)
		if err != nil {
			return nil //nolint:nilerr // truncated section table; elf.NewFile will say so
		}
		shnum = sh.size
		if shstrndx == uint64(elf.SHN_XINDEX) {
			shstrndx = uint64(sh.link)
		}
	}

	// an index of zero means the file has no section name table, so elf.NewFile returns before reading
	// one; an out-of-range index is a file elf.NewFile rejects outright
	if shstrndx == 0 || shstrndx >= shnum {
		return nil
	}
	if shstrndx > uint64(math.MaxInt64)/uint64(shentsize) {
		return nil // the table runs past the end of the address space; elf.NewFile will say so
	}
	off := shoff + int64(shstrndx)*shentsize
	if off < 0 {
		return nil
	}

	sh, err := readSectionHeader(r, class, order, off)
	if err != nil {
		return nil //nolint:nilerr // truncated section table; elf.NewFile will say so
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

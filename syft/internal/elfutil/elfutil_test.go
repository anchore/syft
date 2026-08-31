package elfutil

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// section describes one section to place in a fixture. The compression headers are deliberately
// separable from the payload so a fixture can claim far more than it can deliver, which is the whole
// shape of the attack under test.
type section struct {
	name         string
	typ          elf.SectionType
	flags        elf.SectionFlag
	link         uint32
	body         []byte
	compressed   bool // emit a SHF_COMPRESSED chdr ahead of body
	legacyZlib   bool // emit a 12-byte .zdebug-style ZLIB header ahead of body
	declaredSize uint64
	offsetOf     string // borrow another section's file offset, for SHT_NOBITS fixtures
	shSize       uint64 // override sh_size, since an SHT_NOBITS section's size is not its span in the file
}

type buildOpts struct {
	// nameTable overrides the generated .shstrtab, so a fixture can compress the one section
	// elf.NewFile expands on its own.
	nameTable *section
	// extendedShnum parks the real section count in section 0 and zeroes e_shnum.
	extendedShnum bool
	// xindexShstrndx sets e_shstrndx to SHN_XINDEX so the real index comes from section 0's link.
	xindexShstrndx bool
}

// buildELF assembles a minimal ELF: a null section, then secs, then a generated .shstrtab that
// e_shstrndx points at.
func buildELF(t *testing.T, class elf.Class, order binary.ByteOrder, secs []section, opts buildOpts) []byte {
	t.Helper()

	nameTable := section{name: ".shstrtab", typ: elf.SHT_STRTAB}
	if opts.nameTable != nil {
		nameTable = *opts.nameTable
		nameTable.name = ".shstrtab"
		nameTable.typ = elf.SHT_STRTAB
	}

	all := append([]section{{}}, secs...)
	all = append(all, nameTable)
	shstrndx := len(all) - 1

	// the name table's body is the names of every section, so it has to be built before the payloads
	var names bytes.Buffer
	names.WriteByte(0)
	nameOff := make([]uint32, len(all))
	for i, s := range all {
		if s.name == "" {
			continue
		}
		nameOff[i] = uint32(names.Len())
		names.WriteString(s.name)
		names.WriteByte(0)
	}
	all[shstrndx].body = names.Bytes()
	// a fixture that compresses the name table without rigging a size gets an honest one, so the file is
	// readable rather than merely parseable
	if all[shstrndx].compressed && all[shstrndx].declaredSize == 0 {
		all[shstrndx].declaredSize = uint64(names.Len())
		all[shstrndx].body = deflate(t, names.Bytes())
	}

	is32 := class == elf.ELFCLASS32
	ehsize, shentsize := binary.Size(elf.Header64{}), binary.Size(elf.Section64{})
	machine := elf.EM_X86_64
	if is32 {
		ehsize, shentsize = binary.Size(elf.Header32{}), binary.Size(elf.Section32{})
		machine = elf.EM_386
	}

	shoff := ehsize
	dataOff := shoff + len(all)*shentsize

	// lay the payloads out and remember where each landed, so an SHT_NOBITS fixture can point at one
	payloads := make([][]byte, len(all))
	offsets := make(map[string]uint64)
	cursor := uint64(dataOff)
	for i, s := range all {
		payloads[i] = sectionContent(t, class, order, s)
		offsets[s.name] = cursor
		cursor += uint64(len(payloads[i]))
	}

	var ident [16]byte
	copy(ident[:], elf.ELFMAG)
	ident[elf.EI_CLASS] = byte(class)
	ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	if order == binary.BigEndian {
		ident[elf.EI_DATA] = byte(elf.ELFDATA2MSB)
	}
	ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)

	shnum := uint16(len(all))
	if opts.extendedShnum {
		shnum = 0
	}
	strndx := uint16(shstrndx)
	if opts.xindexShstrndx {
		strndx = uint16(elf.SHN_XINDEX)
	}

	buf := &bytes.Buffer{}
	if is32 {
		write(t, buf, order, elf.Header32{
			Ident: ident, Type: uint16(elf.ET_REL), Machine: uint16(machine), Version: uint32(elf.EV_CURRENT),
			Shoff: uint32(shoff), Ehsize: uint16(ehsize), Shentsize: uint16(shentsize),
			Shnum: shnum, Shstrndx: strndx,
		})
	} else {
		write(t, buf, order, elf.Header64{
			Ident: ident, Type: uint16(elf.ET_REL), Machine: uint16(machine), Version: uint32(elf.EV_CURRENT),
			Shoff: uint64(shoff), Ehsize: uint16(ehsize), Shentsize: uint16(shentsize),
			Shnum: shnum, Shstrndx: strndx,
		})
	}

	off := uint64(dataOff)
	for i, s := range all {
		size := uint64(len(payloads[i]))
		if s.shSize != 0 {
			size = s.shSize
		}
		secOff := off
		if s.offsetOf != "" {
			secOff = offsets[s.offsetOf]
		}
		flags := s.flags
		if s.compressed {
			// the content header and the flag always travel together in a real file
			flags |= elf.SHF_COMPRESSED
		}
		link := s.link
		// section 0 carries the extended count and the extended name table index
		if i == 0 {
			if opts.extendedShnum {
				size = uint64(len(all))
			}
			if opts.xindexShstrndx {
				link = uint32(shstrndx)
			}
		}
		if is32 {
			write(t, buf, order, elf.Section32{
				Name: nameOff[i], Type: uint32(s.typ), Flags: uint32(flags), Link: link,
				Off: uint32(secOff), Size: uint32(size), Addralign: 1,
			})
		} else {
			write(t, buf, order, elf.Section64{
				Name: nameOff[i], Type: uint32(s.typ), Flags: uint64(flags), Link: link,
				Off: secOff, Size: size, Addralign: 1,
			})
		}
		off += uint64(len(payloads[i]))
	}

	require.Equal(t, dataOff, buf.Len(), "fixture layout drifted from the declared offsets")
	for _, p := range payloads {
		buf.Write(p)
	}
	return buf.Bytes()
}

// sectionContent wraps the body in whichever compression header the fixture asks for.
func sectionContent(t *testing.T, class elf.Class, order binary.ByteOrder, s section) []byte {
	t.Helper()

	switch {
	case s.legacyZlib:
		hdr := make([]byte, legacyZlibHeaderSize)
		copy(hdr, "ZLIB")
		binary.BigEndian.PutUint64(hdr[4:], s.declaredSize)
		return append(hdr, s.body...)
	case s.compressed:
		buf := &bytes.Buffer{}
		if class == elf.ELFCLASS32 {
			write(t, buf, order, elf.Chdr32{
				Type: uint32(elf.COMPRESS_ZLIB), Size: uint32(s.declaredSize), Addralign: 1,
			})
		} else {
			write(t, buf, order, elf.Chdr64{
				Type: uint32(elf.COMPRESS_ZLIB), Size: s.declaredSize, Addralign: 1,
			})
		}
		buf.Write(s.body)
		return buf.Bytes()
	default:
		return s.body
	}
}

func write(t *testing.T, w io.Writer, order binary.ByteOrder, v any) {
	t.Helper()
	require.NoError(t, binary.Write(w, order, v))
}

// deflate returns a real zlib stream, so a fixture using it actually delivers the bytes it promises.
func deflate(t *testing.T, payload []byte) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	zw := zlib.NewWriter(buf)
	_, err := zw.Write(payload)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// classes is the matrix every structural case runs under, since the header layouts differ per class and
// the compression header's size field is a different width in each.
var classes = []struct {
	name  string
	class elf.Class
	order binary.ByteOrder
}{
	{"64-bit little-endian", elf.ELFCLASS64, binary.LittleEndian},
	{"64-bit big-endian", elf.ELFCLASS64, binary.BigEndian},
	{"32-bit little-endian", elf.ELFCLASS32, binary.LittleEndian},
	{"32-bit big-endian", elf.ELFCLASS32, binary.BigEndian},
}

const overLimit = maxDeclaredSectionSize + 1

func TestNewFile_RejectsOversizedReachableSections(t *testing.T) {
	tests := []struct {
		name    string
		secs    []section
		opts    buildOpts
		wantErr string
	}{
		{
			name: "compressed .symtab",
			secs: []section{
				{name: ".symtab", typ: elf.SHT_SYMTAB, link: 2, compressed: true, declaredSize: overLimit},
				{name: ".strtab", typ: elf.SHT_STRTAB},
			},
			wantErr: `".symtab"`,
		},
		{
			name: "the string table a .symtab links to",
			secs: []section{
				{name: ".symtab", typ: elf.SHT_SYMTAB, link: 2},
				{name: ".strtab", typ: elf.SHT_STRTAB, compressed: true, declaredSize: overLimit},
			},
			wantErr: `".strtab"`,
		},
		{
			name: "compressed .dynsym",
			secs: []section{
				{name: ".dynsym", typ: elf.SHT_DYNSYM, link: 2, compressed: true, declaredSize: overLimit},
				{name: ".dynstr", typ: elf.SHT_STRTAB},
			},
			wantErr: `".dynsym"`,
		},
		{
			name: "compressed .dynamic",
			secs: []section{
				{name: ".dynamic", typ: elf.SHT_DYNAMIC, compressed: true, declaredSize: overLimit},
			},
			wantErr: `".dynamic"`,
		},
		{
			name: "compressed .note.package, reached by name rather than type",
			secs: []section{
				{name: ".note.package", typ: elf.SHT_NOTE, compressed: true, declaredSize: overLimit},
			},
			wantErr: `".note.package"`,
		},
		{
			name: "compressed .modinfo, read by the kernel module cataloger",
			secs: []section{
				{name: ".modinfo", typ: elf.SHT_PROGBITS, compressed: true, declaredSize: overLimit},
			},
			wantErr: `".modinfo"`,
		},
		{
			// File.DynamicSymbols reads these via gnuVersionInit without the caller naming them
			name: "compressed .gnu.version alongside a .dynsym",
			secs: []section{
				{name: ".dynsym", typ: elf.SHT_DYNSYM, link: 2},
				{name: ".dynstr", typ: elf.SHT_STRTAB},
				{name: ".gnu.version", typ: elf.SHT_GNU_VERSYM, compressed: true, declaredSize: overLimit},
			},
			wantErr: `".gnu.version"`,
		},
		{
			name: "compressed .gnu.version_r alongside a .dynsym",
			secs: []section{
				{name: ".dynsym", typ: elf.SHT_DYNSYM, link: 2},
				{name: ".dynstr", typ: elf.SHT_STRTAB},
				{name: ".gnu.version_r", typ: elf.SHT_GNU_VERNEED, compressed: true, declaredSize: overLimit},
			},
			wantErr: `".gnu.version_r"`,
		},
		{
			name: "compressed .gnu.version_d alongside a .dynsym",
			secs: []section{
				{name: ".dynsym", typ: elf.SHT_DYNSYM, link: 2},
				{name: ".dynstr", typ: elf.SHT_STRTAB},
				{name: ".gnu.version_d", typ: elf.SHT_GNU_VERDEF, compressed: true, declaredSize: overLimit},
			},
			wantErr: `".gnu.version_d"`,
		},
		{
			// the one section elf.NewFile expands itself, so this has to be caught before the parse
			name:    "compressed section name table",
			opts:    buildOpts{nameTable: &section{compressed: true, declaredSize: overLimit}},
			wantErr: "section name table",
		},
		{
			// debug/elf gates the legacy form on the name, so a reachable section named this way reaches it
			name: "legacy .zdebug header on a section reached by type",
			secs: []section{
				{name: ".zdebug_symtab", typ: elf.SHT_SYMTAB, link: 2, legacyZlib: true, declaredSize: overLimit},
				{name: ".strtab", typ: elf.SHT_STRTAB},
			},
			wantErr: `".zdebug_symtab"`,
		},
	}

	for _, tt := range tests {
		for _, c := range classes {
			t.Run(tt.name+"/"+c.name, func(t *testing.T) {
				data := buildELF(t, c.class, c.order, tt.secs, tt.opts)
				_, err := NewFile(bytes.NewReader(data))
				require.Error(t, err)
				// the fixtures are hand-assembled ELF bytes, so a bad one would satisfy require.Error on
				// its own. Naming the section proves the rejection is the one we set up, and naming the
				// limit proves it came from this package rather than from debug/elf.
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Contains(t, err.Error(), fmt.Sprint(maxDeclaredSectionSize))
			})
		}
	}
}

// TestNewFile_AcceptsWhatDebugELFWouldNotExpand covers the false-negative direction: rejecting a whole
// binary over a section debug/elf is never driven to decompress drops real packages from the SBOM.
//
// Every fixture here is a file debug/elf parses without complaint, and every one must come back from
// NewFile without complaint too. An oversized claim is only worth rejecting when debug/elf can actually
// be made to allocate against it, so a claim it will never act on has to be ignored outright rather than
// merely tolerated.
func TestNewFile_AcceptsWhatDebugELFWouldNotExpand(t *testing.T) {
	tests := []struct {
		name string
		secs []section
		why  string
	}{
		{
			// only File.DWARF expands a .debug_* section, and nothing in syft calls it, so this claim is
			// never acted on. reachableSections leaves DWARF out on purpose: compressed debug info is
			// routinely enormous in a legitimate binary, and bounding it would skip the binary entirely.
			//
			// non-allocable and SHF_COMPRESSED is deliberately the one shape debug/elf will expand, so the
			// name is the only thing keeping this accepted. Adding SHF_ALLOC would make it pass for the
			// allocable case's reason below and stop saying anything about DWARF.
			name: "oversized compressed DWARF",
			secs: []section{
				{name: ".debug_info", typ: elf.SHT_PROGBITS, compressed: true, declaredSize: overLimit},
			},
			why: "syft never calls File.DWARF, so debug/elf is never asked to expand it",
		},
		{
			// the same section in the older form toolchains emitted before SHF_COMPRESSED existed. The
			// header is different, the reader that would expand it is the same one syft never calls.
			//
			// SHF_COMPRESSED is deliberately absent: with it set, debug/elf takes the modern path and the
			// legacy header is never consulted, so the .zdebug name gate would go untested.
			name: "oversized legacy .zdebug DWARF",
			secs: []section{
				{name: ".zdebug_info", typ: elf.SHT_PROGBITS, legacyZlib: true, declaredSize: overLimit},
			},
			why: "same, via the legacy form",
		},
		{
			// reachable by type and named the way debug/elf gates the legacy form on, so the name half of
			// that gate passes and the magic is the only thing left to reject the claim. Without the magic
			// check the 0xff bytes behind it decode as a declared size of 2^64-1.
			name: "a .zdebug-named reachable section whose bytes are not a legacy header",
			secs: []section{
				{name: ".zdebug_symtab", typ: elf.SHT_SYMTAB, link: 2,
					body: append([]byte("NOPE"), bytes.Repeat([]byte{0xff}, 32)...)},
				{name: ".strtab", typ: elf.SHT_STRTAB},
			},
			why: "the legacy form needs the magic as well as the name",
		},
		{
			// the other half of the same gate: fewer bytes present than a legacy header needs. The magic is
			// intact and some of the size field is present, so a short read has to read as "no claim"
			// rather than as a size decoded out of a partly-filled buffer, which here would be huge.
			name: "a .zdebug-named reachable section too short to hold a legacy header",
			secs: []section{
				{name: ".zdebug_symtab", typ: elf.SHT_SYMTAB, link: 2,
					body: append([]byte("ZLIB"), bytes.Repeat([]byte{0xff}, 4)...)},
				{name: ".strtab", typ: elf.SHT_STRTAB},
			},
			why: "a truncated legacy header is not a claim",
		},
		{
			// an ordinary uncompressed note that happens to open with those four bytes. debug/elf takes
			// the legacy path only for a .zdebug-prefixed name, so it reads this as content and nothing
			// here is a size claim at all. A check that sniffed for the magic instead would decode the
			// 0xff padding behind it as a declared size and throw the binary away.
			//
			// .note.package because it has to be a section syft actually reads, or reachableSections skips
			// it and the case passes without exercising anything. No flags for the same reason the name is
			// not .zdebug-prefixed: either one would put debug/elf on a path where the bytes are a header.
			name: "an uncompressed section whose bytes happen to start with ZLIB",
			secs: []section{
				{name: ".note.package", typ: elf.SHT_NOTE, body: append([]byte("ZLIB"), bytes.Repeat([]byte{0xff}, 32)...)},
			},
			why: "debug/elf gates the legacy form on the section name, not the magic, so this is not a claim at all",
		},
		{
			// a section that occupies memory at runtime cannot be compressed on disk, so (*Section).Open
			// hands back the raw bytes rather than expanding one that says it is. The claim is real and
			// oversized, and still costs nothing.
			//
			// this is the ".symtab" reject case with one bit added: .data is read by name just as .symtab
			// is, so SHF_ALLOC is the only reason the two outcomes differ.
			name: "an allocable compressed section",
			secs: []section{
				{name: ".data", typ: elf.SHT_PROGBITS, flags: elf.SHF_COMPRESSED | elf.SHF_ALLOC,
					compressed: true, declaredSize: overLimit},
			},
			why: "debug/elf refuses to decompress an allocable section",
		},
		{
			// the hardest one to see: sh_offset points into .rodata's payload, so elf.NewFile reads that
			// compression header and .data comes back carrying an oversized Size of its own. Reading Size
			// alone would reject here, but a SHT_NOBITS section holds no file bytes and its reader yields
			// none, so the size is never allocated against. sh_size is set by hand because such a section
			// has a size without occupying any of the file, and a zero one is a file debug/elf rejects.
			//
			// SHF_COMPRESSED has to be set for the size to be a claim at all, and .data has to be the
			// borrower rather than the donor, since the donor is unreachable by name and never checked.
			name: "an SHT_NOBITS section borrowing another section's compression header",
			secs: []section{
				{name: ".rodata", typ: elf.SHT_PROGBITS, compressed: true, declaredSize: overLimit},
				{name: ".data", typ: elf.SHT_NOBITS, flags: elf.SHF_COMPRESSED, offsetOf: ".rodata",
					shSize: 4096},
			},
			why: "debug/elf never yields bytes for SHT_NOBITS, whatever Size it ends up carrying",
		},
		{
			// a string table is reached through some symbol table's sh_link, never on its own, so one
			// nothing points at is one nothing reads. This is the reject test's linked-.strtab case with
			// the .symtab removed, and it is the case an implementation that bounded every SHT_STRTAB
			// rather than following the links would fail.
			name: "an oversized string table that no symbol table links",
			secs: []section{
				{name: ".strtab", typ: elf.SHT_STRTAB, compressed: true, declaredSize: overLimit},
			},
			why: "reachability runs through sh_link, not section type",
		},
	}

	for _, tt := range tests {
		for _, c := range classes {
			t.Run(tt.name+"/"+c.name, func(t *testing.T) {
				data := buildELF(t, c.class, c.order, tt.secs, buildOpts{})

				// "elfutil accepted it" only means something if debug/elf accepts it too, so a fixture
				// that drifts into being malformed fails here rather than passing for the wrong reason
				_, err := elf.NewFile(bytes.NewReader(data))
				require.NoError(t, err, "fixture is supposed to be a file debug/elf accepts")

				_, err = NewFile(bytes.NewReader(data))
				require.NoError(t, err, tt.why)
			})
		}
	}
}

// TestNewFile_AcceptsAndReadsSectionUnderTheLimit guards the risk the bound introduces: a legitimately
// compressed section must still be readable, not merely accepted.
func TestNewFile_AcceptsAndReadsSectionUnderTheLimit(t *testing.T) {
	for _, c := range classes {
		t.Run(c.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte("syft"), 4096)
			data := buildELF(t, c.class, c.order, []section{
				{name: ".note.package", typ: elf.SHT_NOTE, flags: elf.SHF_COMPRESSED,
					compressed: true, declaredSize: uint64(len(payload)), body: deflate(t, payload)},
			}, buildOpts{})

			f, err := NewFile(bytes.NewReader(data))
			require.NoError(t, err)

			got, err := f.Section(".note.package").Data()
			require.NoError(t, err)
			assert.Equal(t, payload, got)
		})
	}
}

// TestNewFile_AcceptsAndReadsCompressedSectionNameTable covers the other half of CheckSectionNameTable.
// That check runs before the parse, off a hand-decoded section header rather than anything debug/elf has
// resolved, so a version of it that rejected every compressed name table outright, or that read the size
// out of the wrong offset, would still pass every rejection case. Resolving the names proves the file was
// left intact and not merely let through.
func TestNewFile_AcceptsAndReadsCompressedSectionNameTable(t *testing.T) {
	for _, c := range classes {
		t.Run(c.name, func(t *testing.T) {
			data := buildELF(t, c.class, c.order,
				[]section{{name: ".note.package", typ: elf.SHT_NOTE}},
				buildOpts{nameTable: &section{compressed: true}})

			f, err := NewFile(bytes.NewReader(data))
			require.NoError(t, err)
			assert.NotNil(t, f.Section(".note.package"), "section names did not survive the name table")
		})
	}
}

// TestNewFile_BombDoesNotAllocate is the end-to-end case: a real zlib stream that genuinely delivers
// every byte its header promises, so without the bound debug/elf allocates all of them.
func TestNewFile_BombDoesNotAllocate(t *testing.T) {
	const declared = maxDeclaredSectionSize + 1
	compressed := deflate(t, make([]byte, declared))
	t.Logf("%d declared bytes compress to %d", declared, len(compressed))

	data := buildELF(t, elf.ELFCLASS64, binary.LittleEndian, []section{
		{name: ".symtab", typ: elf.SHT_SYMTAB, link: 2, flags: elf.SHF_COMPRESSED,
			compressed: true, declaredSize: declared, body: compressed},
		{name: ".strtab", typ: elf.SHT_STRTAB},
	}, buildOpts{})

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	_, err := NewFile(bytes.NewReader(data))

	runtime.ReadMemStats(&after)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "over the")

	// the guard has to reject before the allocation, not after it. The margin is loose on purpose: this
	// is asserting "nothing near the declared size was allocated", not a precise budget.
	const margin = 32 * 1024 * 1024
	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(margin),
		"parsing allocated far more than the input warrants")
}

// TestNewFile_MatchesDebugELFOnStructuralEdges pins the invariant the passthrough returns depend on:
// wherever elfutil declines to check, elf.NewFile must still be the one deciding.
func TestNewFile_MatchesDebugELFOnStructuralEdges(t *testing.T) {
	tests := []struct {
		name string
		secs []section
		opts buildOpts
	}{
		{name: "plain file", secs: []section{{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC}}},
		{name: "extended section count", opts: buildOpts{extendedShnum: true}},
		{name: "extended name table index", opts: buildOpts{xindexShstrndx: true}},
		{name: "both extended forms", opts: buildOpts{extendedShnum: true, xindexShstrndx: true}},
		{
			name: "symtab linking a nonexistent string table",
			secs: []section{{name: ".symtab", typ: elf.SHT_SYMTAB, link: 99}},
		},
	}

	for _, tt := range tests {
		for _, c := range classes {
			t.Run(tt.name+"/"+c.name, func(t *testing.T) {
				data := buildELF(t, c.class, c.order, tt.secs, tt.opts)

				_, want := elf.NewFile(bytes.NewReader(data))
				_, got := NewFile(bytes.NewReader(data))

				if want == nil {
					assert.NoError(t, got, "elfutil rejected a file debug/elf accepts")
					return
				}
				require.Error(t, got, "elfutil accepted a file debug/elf rejects")
			})
		}
	}
}

// TestNewFile_ExtendedShnumOverflowStillChecks covers the case a signed conversion used to swallow: a
// count that does not fit an int64 must not read as "no sections" and skip the check.
func TestNewFile_ExtendedShnumOverflowStillChecks(t *testing.T) {
	data := buildELF(t, elf.ELFCLASS64, binary.LittleEndian, nil,
		buildOpts{nameTable: &section{compressed: true, declaredSize: overLimit}})

	// rewrite section 0's size to a count that overflows int64, and zero e_shnum so it is consulted
	// e_shnum sits at 0x3c in an Elf64_Ehdr, and sh_size at +32 in the Elf64_Shdr that follows it
	shoff := binary.Size(elf.Header64{})
	binary.LittleEndian.PutUint16(data[0x3c:], 0)
	binary.LittleEndian.PutUint64(data[shoff+32:], uint64(1)<<63)

	_, err := NewFile(bytes.NewReader(data))
	require.Error(t, err, "a bogus section count must not disable the check")
}

func TestNewFile_PassesThroughNonELF(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"shorter than e_ident", []byte{0x7f, 'E'}},
		{"bad magic", bytes.Repeat([]byte{0xab}, 128)},
		{"bad class", func() []byte {
			b := bytes.Repeat([]byte{0}, 128)
			copy(b, elf.ELFMAG)
			b[elf.EI_CLASS] = 9
			return b
		}()},
		{"bad byte order", func() []byte {
			b := bytes.Repeat([]byte{0}, 128)
			copy(b, elf.ELFMAG)
			b[elf.EI_CLASS] = byte(elf.ELFCLASS64)
			b[elf.EI_DATA] = 9
			return b
		}()},
		{"truncated after the header", func() []byte {
			data := buildELF(t, elf.ELFCLASS64, binary.LittleEndian, nil, buildOpts{})
			return data[:binary.Size(elf.Header64{})+4]
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, want := elf.NewFile(bytes.NewReader(tt.data))
			_, got := NewFile(bytes.NewReader(tt.data))

			require.Error(t, want, "fixture is supposed to be rejected by debug/elf")
			require.Error(t, got)
			// the rejection must be debug/elf's, phrased its way, not ours
			assert.NotContains(t, got.Error(), "over the")
			assert.Equal(t, fmt.Sprint(want), fmt.Sprint(got))
		})
	}
}

package elfutil

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

const buildInfoName = ".go.buildinfo"

func TestHasSectionNamed(t *testing.T) {
	withBuildInfo := []section{
		{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, body: []byte{0xc3}},
		{name: buildInfoName, typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, body: []byte("\xff Go buildinf:")},
		{name: ".data", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, body: []byte{1, 2, 3}},
	}
	withoutBuildInfo := []section{
		{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, body: []byte{0xc3}},
		{name: ".data", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, body: []byte{1, 2, 3}},
	}
	// names that share bytes with the one asked about must not match: a name is the whole string up to
	// the NUL, so a longer name is a different name and so is a shorter one
	nearMisses := []section{
		{name: buildInfoName + "2", typ: elf.SHT_PROGBITS, body: []byte{1}},
		{name: buildInfoName[:len(buildInfoName)-1], typ: elf.SHT_PROGBITS, body: []byte{2}},
		{name: "x" + buildInfoName, typ: elf.SHT_PROGBITS, body: []byte{3}},
	}

	tests := []struct {
		name      string
		secs      []section
		opts      buildOpts
		wantFound bool
		wantOK    bool
	}{
		{name: "present", secs: withBuildInfo, wantFound: true, wantOK: true},
		{name: "absent", secs: withoutBuildInfo, wantFound: false, wantOK: true},
		{name: "near misses only", secs: nearMisses, wantFound: false, wantOK: true},
		{name: "present among near misses", secs: append(append([]section{}, nearMisses...), withBuildInfo...), wantFound: true, wantOK: true},
		{name: "no sections but the name table", secs: nil, wantFound: false, wantOK: true},
		// the extended forms are only valid, to debug/elf, for a file with at least SHN_LORESERVE
		// sections, which is what the large fixtures are; the same forms on a small file are rejected by
		// elf.NewFile before it reads a name, so no answer can be given for them
		{name: "present with extended section count", secs: manySections(t, true), opts: buildOpts{extendedShnum: true}, wantFound: true, wantOK: true},
		{name: "present with both extended forms", secs: manySections(t, true), opts: buildOpts{extendedShnum: true, xindexShstrndx: true}, wantFound: true, wantOK: true},
		{name: "absent with both extended forms", secs: manySections(t, false), opts: buildOpts{extendedShnum: true, xindexShstrndx: true}, wantFound: false, wantOK: true},
		{name: "extended count on a small file", secs: withBuildInfo, opts: buildOpts{extendedShnum: true}, wantFound: false, wantOK: false},
		{name: "extended name table index on a small file", secs: withBuildInfo, opts: buildOpts{xindexShstrndx: true}, wantFound: false, wantOK: false},
		{name: "both extended forms on a small file", secs: withBuildInfo, opts: buildOpts{extendedShnum: true, xindexShstrndx: true}, wantFound: false, wantOK: false},
		{
			name: "compressed name table cannot be read without a parse",
			secs: withBuildInfo, opts: buildOpts{nameTable: &section{compressed: true}},
			wantFound: false, wantOK: false,
		},
	}

	for _, c := range classes {
		t.Run(c.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					data := buildELF(t, c.class, c.order, tt.secs, tt.opts)
					found, ok := HasSectionNamed(bytes.NewReader(data), buildInfoName)
					assert.Equal(t, tt.wantOK, ok, "ok")
					assert.Equal(t, tt.wantFound, found, "found")

					// whenever an answer is given it has to be the one debug/elf would give, and a file
					// debug/elf rejects before reading names gets no answer
					f, err := elf.NewFile(bytes.NewReader(data))
					if err != nil {
						assert.False(t, ok, "debug/elf rejects this file (%v), so there is no answer to give", err)
						return
					}
					if ok {
						assert.Equal(t, f.Section(buildInfoName) != nil, found, "answer disagrees with debug/elf")
					}
				})
			}
		})
	}
}

// manySections is enough sections for the extended numbering forms to be legal: a count past
// SHN_LORESERVE, which also puts the name table (the last section) at an index past it, as SHN_XINDEX
// requires. The null section and the name table are added by the builder; .go.buildinfo is among the
// rest or not.
func manySections(t *testing.T, withBuildInfo bool) []section {
	t.Helper()
	secs := make([]section, 0, int(elf.SHN_LORESERVE))
	for i := 0; len(secs) < int(elf.SHN_LORESERVE)-1; i++ {
		if withBuildInfo && i == 1234 {
			secs = append(secs, section{name: buildInfoName, typ: elf.SHT_PROGBITS, body: []byte{1}})
			continue
		}
		secs = append(secs, section{name: fmt.Sprintf(".s%d", i), typ: elf.SHT_PROGBITS, body: []byte{byte(i)}})
	}
	return secs
}

func TestHasSectionNamed_UnanswerableFiles(t *testing.T) {
	valid := buildELF(t, elf.ELFCLASS64, binary.LittleEndian, []section{
		{name: buildInfoName, typ: elf.SHT_PROGBITS, body: []byte{1}},
	}, buildOpts{})
	shoff := binary.Size(elf.Header64{})
	shentsize := binary.Size(elf.Section64{})

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"not an ELF", []byte("MZ\x90\x00 this is not an ELF file, whatever the extension says")},
		{"no section table", func() []byte {
			b := bytes.Clone(valid)
			binary.LittleEndian.PutUint64(b[0x28:], 0) // e_shoff
			binary.LittleEndian.PutUint16(b[0x3c:], 0) // e_shnum
			binary.LittleEndian.PutUint16(b[0x3e:], 0) // e_shstrndx
			return b
		}()},
		{"name offset past the table", func() []byte {
			b := bytes.Clone(valid)
			// sh_name is the first field of the Elf64_Shdr for section 1
			binary.LittleEndian.PutUint32(b[shoff+shentsize:], 0xffffffff)
			return b
		}()},
		{"name table of the wrong type", func() []byte {
			b := bytes.Clone(valid)
			// the name table is the last section; sh_type sits at +4
			last := shoff + 2*shentsize
			binary.LittleEndian.PutUint32(b[last+4:], uint32(elf.SHT_PROGBITS))
			return b
		}()},
		{"truncated before the names", func() []byte {
			return valid[:shoff+3*shentsize+2]
		}()},
		{"truncated inside the section headers", func() []byte {
			return valid[:shoff+shentsize+8]
		}()},
		{"section count overflowing the address space", func() []byte {
			b := bytes.Clone(valid)
			binary.LittleEndian.PutUint16(b[0x3c:], 0)                 // e_shnum: consult section 0
			binary.LittleEndian.PutUint64(b[shoff+32:], uint64(1)<<63) // section 0 sh_size
			return b
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, ok := HasSectionNamed(bytes.NewReader(tt.data), buildInfoName)
			assert.False(t, ok, "a file that cannot be read is not an answer")
			assert.False(t, found)
		})
	}
}

func TestHasSectionNamed_NameFlushWithEndOfFile(t *testing.T) {
	// the name table is the last thing in the file and the name asked about is its last entry, so the
	// read of that name ends exactly at EOF. bytes.Reader reports io.EOF alongside a full read there, and
	// the count has to win over the error.
	data := buildELF(t, elf.ELFCLASS64, binary.LittleEndian, []section{
		{name: ".text", typ: elf.SHT_PROGBITS, body: []byte{0xc3}},
	}, buildOpts{})
	// the generated name table is "\x00.text\x00.shstrtab\x00"; ask for its last name
	found, ok := HasSectionNamed(bytes.NewReader(data), ".shstrtab")
	assert.True(t, ok)
	assert.True(t, found)
}

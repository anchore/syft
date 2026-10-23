package executable

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/elfutil"
	"github.com/anchore/syft/syft/internal/unionreader"
)

func Test_findELFSecurityFeatures(t *testing.T) {

	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("testdata/elf", fixture))
		require.NoError(t, err)
		return f
	}

	tests := []struct {
		name         string
		fixture      string
		want         *file.ELFSecurityFeatures
		wantErr      require.ErrorAssertionFunc
		wantStripped bool
	}{
		{
			name:    "detect canary",
			fixture: "bin/with_canary",
			want: &file.ELFSecurityFeatures{
				StackCanary:              boolRef(true), // ! important !
				RelocationReadOnly:       file.RelocationReadOnlyNone,
				LlvmSafeStack:            boolRef(false),
				LlvmControlFlowIntegrity: boolRef(false),
				ClangFortifySource:       boolRef(false),
			},
		},
		{
			name:    "detect nx",
			fixture: "bin/with_nx",
			want: &file.ELFSecurityFeatures{
				StackCanary:              boolRef(false),
				NoExecutable:             true, // ! important !
				RelocationReadOnly:       file.RelocationReadOnlyNone,
				LlvmSafeStack:            boolRef(false),
				LlvmControlFlowIntegrity: boolRef(false),
				ClangFortifySource:       boolRef(false),
			},
		},
		{
			name:    "detect relro",
			fixture: "bin/with_relro",
			want: &file.ELFSecurityFeatures{
				StackCanary:              boolRef(false),
				RelocationReadOnly:       file.RelocationReadOnlyFull, // ! important !
				LlvmSafeStack:            boolRef(false),
				LlvmControlFlowIntegrity: boolRef(false),
				ClangFortifySource:       boolRef(false),
			},
		},
		{
			name:    "detect partial relro",
			fixture: "bin/with_partial_relro",
			want: &file.ELFSecurityFeatures{
				StackCanary:              boolRef(false),
				RelocationReadOnly:       file.RelocationReadOnlyPartial, // ! important !
				LlvmSafeStack:            boolRef(false),
				LlvmControlFlowIntegrity: boolRef(false),
				ClangFortifySource:       boolRef(false),
			},
		},
		{
			name:    "detect pie",
			fixture: "bin/with_pie",
			want: &file.ELFSecurityFeatures{
				StackCanary:                   boolRef(false),
				RelocationReadOnly:            file.RelocationReadOnlyNone,
				PositionIndependentExecutable: true, // ! important !
				DynamicSharedObject:           true, // ! important !
				LlvmSafeStack:                 boolRef(false),
				LlvmControlFlowIntegrity:      boolRef(false),
				ClangFortifySource:            boolRef(false),
			},
		},
		{
			name:    "detect dso",
			fixture: "bin/pie_false_positive.so",
			want: &file.ELFSecurityFeatures{
				StackCanary:                   boolRef(false),
				RelocationReadOnly:            file.RelocationReadOnlyPartial,
				NoExecutable:                  true,
				PositionIndependentExecutable: false, // ! important !
				DynamicSharedObject:           true,  // ! important !
				LlvmSafeStack:                 boolRef(false),
				LlvmControlFlowIntegrity:      boolRef(false),
				ClangFortifySource:            boolRef(false),
			},
		},
		{
			name:    "detect safestack",
			fixture: "bin/with_safestack",
			want: &file.ELFSecurityFeatures{
				NoExecutable:                  true,
				StackCanary:                   boolRef(false),
				RelocationReadOnly:            file.RelocationReadOnlyPartial,
				PositionIndependentExecutable: false,
				DynamicSharedObject:           false,
				LlvmSafeStack:                 boolRef(true), // ! important !
				LlvmControlFlowIntegrity:      boolRef(false),
				ClangFortifySource:            boolRef(false),
			},
		},
		{
			name:    "detect cfi",
			fixture: "bin/with_cfi",
			want: &file.ELFSecurityFeatures{
				NoExecutable:                  true,
				StackCanary:                   boolRef(false),
				RelocationReadOnly:            file.RelocationReadOnlyPartial,
				PositionIndependentExecutable: false,
				DynamicSharedObject:           false,
				LlvmSafeStack:                 boolRef(false),
				LlvmControlFlowIntegrity:      boolRef(true), // ! important !
				ClangFortifySource:            boolRef(false),
			},
		},
		{
			name:    "detect fortify",
			fixture: "bin/with_fortify",
			want: &file.ELFSecurityFeatures{
				NoExecutable:                  true,
				StackCanary:                   boolRef(false),
				RelocationReadOnly:            file.RelocationReadOnlyPartial,
				PositionIndependentExecutable: false,
				DynamicSharedObject:           false,
				LlvmSafeStack:                 boolRef(false),
				LlvmControlFlowIntegrity:      boolRef(false),
				ClangFortifySource:            boolRef(true), // ! important !
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := elf.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)

			got := findELFSecurityFeatures(f)

			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("findELFSecurityFeatures() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func Test_elfHasEntrypoint(t *testing.T) {

	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("testdata/shared-info", fixture))
		require.NoError(t, err)
		return f
	}

	tests := []struct {
		name    string
		fixture string
		want    bool
	}{
		{
			name:    "shared lib",
			fixture: "bin/libhello.so",
			want:    false,
		},
		{
			name:    "application",
			fixture: "bin/hello_linux",
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := elf.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)
			assert.Equal(t, tt.want, elfHasEntrypoint(f))
		})
	}
}

func Test_elfHasExports(t *testing.T) {
	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("testdata/shared-info", fixture))
		require.NoError(t, err)
		return f
	}

	tests := []struct {
		name    string
		fixture string
		want    bool
	}{
		{
			name:    "shared lib",
			fixture: "bin/libhello.so",
			want:    true,
		},
		{
			name:    "application",
			fixture: "bin/hello_linux",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := elf.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)
			assert.Equal(t, tt.want, elfHasExports(f))
			require.NoError(t, err)
		})
	}
}

func Test_hasElfDynTag(t *testing.T) {
	dynEntry := func(class elf.Class, tag elf.DynTag) []byte {
		if class == elf.ELFCLASS32 {
			return binary.LittleEndian.AppendUint32(binary.LittleEndian.AppendUint32(nil, uint32(tag)), 0)
		}
		return binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint64(nil, uint64(tag)), 0)
	}

	tests := []struct {
		name    string
		class   elf.Class
		dynamic []byte
		want    bool
	}{
		{
			name:    "32-bit tag present",
			class:   elf.ELFCLASS32,
			dynamic: dynEntry(elf.ELFCLASS32, elf.DT_BIND_NOW),
			want:    true,
		},
		{
			name:    "64-bit tag present",
			class:   elf.ELFCLASS64,
			dynamic: dynEntry(elf.ELFCLASS64, elf.DT_BIND_NOW),
			want:    true,
		},
		{
			name:    "64-bit tag absent",
			class:   elf.ELFCLASS64,
			dynamic: dynEntry(elf.ELFCLASS64, elf.DT_NULL),
			want:    false,
		},
		{
			name:    "32-bit truncated dynamic section",
			class:   elf.ELFCLASS32,
			dynamic: dynEntry(elf.ELFCLASS32, elf.DT_BIND_NOW)[:4],
			want:    false,
		},
		{
			name:    "64-bit truncated dynamic section",
			class:   elf.ELFCLASS64,
			dynamic: dynEntry(elf.ELFCLASS64, elf.DT_BIND_NOW)[:12],
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := elf.NewFile(bytes.NewReader(elfWithDynamicSection(t, tt.class, tt.dynamic)))
			require.NoError(t, err)
			assert.Equal(t, tt.want, hasElfDynTag(f, elf.DT_BIND_NOW))
		})
	}
}

// elfWithDynamicSection builds a little-endian ELF holding only a null section and a SHT_DYNAMIC section.
func elfWithDynamicSection(t *testing.T, class elf.Class, dynamic []byte) []byte {
	t.Helper()
	return elfWithSection(t, class, elf.SHT_DYNAMIC, 1, dynamic)
}

// elfWithSection builds a little-endian ELF holding only a null section and one section of the given type.
func elfWithSection(t *testing.T, class elf.Class, typ elf.SectionType, align uint64, data []byte) []byte {
	t.Helper()
	ident := [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(class), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}
	var buf bytes.Buffer
	write := func(v any) {
		require.NoError(t, binary.Write(&buf, binary.LittleEndian, v))
	}

	if class == elf.ELFCLASS32 {
		ehsize, shentsize := binary.Size(elf.Header32{}), binary.Size(elf.Section32{})
		dataOff := ehsize + 2*shentsize
		write(elf.Header32{
			Ident: ident, Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_386), Version: uint32(elf.EV_CURRENT),
			Shoff: uint32(ehsize), Ehsize: uint16(ehsize), Shentsize: uint16(shentsize), Shnum: 2,
		})
		write(elf.Section32{})
		write(elf.Section32{Type: uint32(typ), Off: uint32(dataOff), Size: uint32(len(data)), Addralign: uint32(align)})
	} else {
		ehsize, shentsize := binary.Size(elf.Header64{}), binary.Size(elf.Section64{})
		dataOff := ehsize + 2*shentsize
		write(elf.Header64{
			Ident: ident, Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
			Shoff: uint64(ehsize), Ehsize: uint16(ehsize), Shentsize: uint16(shentsize), Shnum: 2,
		})
		write(elf.Section64{})
		write(elf.Section64{Type: uint32(typ), Off: uint64(dataOff), Size: uint64(len(data)), Addralign: align})
	}
	buf.Write(data)
	return buf.Bytes()
}

// encodeELFNote encodes a single little-endian Elf_Nhdr record, padding name and descriptor to align.
func encodeELFNote(owner string, typ uint32, desc []byte, align int) []byte {
	pad := func(b []byte) []byte {
		for len(b)%align != 0 {
			b = append(b, 0)
		}
		return b
	}
	name := append([]byte(owner), 0)
	out := binary.LittleEndian.AppendUint32(nil, uint32(len(name)))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(desc)))
	out = binary.LittleEndian.AppendUint32(out, typ)
	out = pad(append(out, name...))
	return pad(append(out, desc...))
}

func Test_findELFIdentifiers(t *testing.T) {
	sha1ID := bytes.Repeat([]byte{0xab}, 20)
	customID := []byte{0xde, 0xad, 0xbe, 0xef}
	longID := bytes.Repeat([]byte{0x01}, 32)

	buildID := func(v []byte) file.ExecutableIdentifier {
		return file.ExecutableIdentifier{Kind: file.ELFGNUBuildID, Value: hex.EncodeToString(v)}
	}
	const ntGNUABITag, ntGNUProperty = 1, 5

	tests := []struct {
		name        string
		elf         []byte
		sectionName string
		want        []file.ExecutableIdentifier
	}{
		{
			name:        "sha1-length build id",
			elf:         elfWithSection(t, elf.ELFCLASS64, elf.SHT_NOTE, 4, encodeELFNote("GNU", ntGNUBuildID, sha1ID, 4)),
			sectionName: ".note.gnu.build-id",
			want:        []file.ExecutableIdentifier{buildID(sha1ID)},
		},
		{
			name:        "caller-chosen short build id",
			elf:         elfWithSection(t, elf.ELFCLASS32, elf.SHT_NOTE, 4, encodeELFNote("GNU", ntGNUBuildID, customID, 4)),
			sectionName: ".note.gnu.build-id",
			want:        []file.ExecutableIdentifier{buildID(customID)},
		},
		{
			name: "build id after other notes in the same section",
			elf: elfWithSection(t, elf.ELFCLASS64, elf.SHT_NOTE, 4, append(
				encodeELFNote("GNU", ntGNUABITag, make([]byte, 16), 4),
				encodeELFNote("GNU", ntGNUBuildID, longID, 4)...,
			)),
			sectionName: ".note.gnu.build-id",
			want:        []file.ExecutableIdentifier{buildID(longID)},
		},
		{
			name: "8-byte aligned note section",
			elf: elfWithSection(t, elf.ELFCLASS64, elf.SHT_NOTE, 8, append(
				encodeELFNote("GNU", ntGNUProperty, make([]byte, 12), 8),
				encodeELFNote("GNU", ntGNUBuildID, customID, 8)...,
			)),
			sectionName: ".note.gnu.build-id",
			want:        []file.ExecutableIdentifier{buildID(customID)},
		},
		{
			name: "duplicate build ids",
			elf: elfWithSection(t, elf.ELFCLASS64, elf.SHT_NOTE, 4, bytes.Repeat(
				encodeELFNote("GNU", ntGNUBuildID, customID, 4), 2,
			)),
			sectionName: ".note.gnu.build-id",
			want:        []file.ExecutableIdentifier{buildID(customID)},
		},
		{
			name:        "build id in another section is ignored",
			elf:         elfWithSection(t, elf.ELFCLASS64, elf.SHT_NOTE, 4, encodeELFNote("GNU", ntGNUBuildID, sha1ID, 4)),
			sectionName: ".note.other",
		},
		{
			name:        "build-id section with another section type is ignored",
			elf:         elfWithSection(t, elf.ELFCLASS64, elf.SHT_PROGBITS, 4, encodeELFNote("GNU", ntGNUBuildID, sha1ID, 4)),
			sectionName: ".note.gnu.build-id",
		},
		{
			name:        "build-id section with another owner is ignored",
			elf:         elfWithSection(t, elf.ELFCLASS64, elf.SHT_NOTE, 4, encodeELFNote("FDO", ntGNUBuildID, sha1ID, 4)),
			sectionName: ".note.gnu.build-id",
		},
		{
			name:        "build-id section with another note type is ignored",
			elf:         elfWithSection(t, elf.ELFCLASS64, elf.SHT_NOTE, 4, encodeELFNote("GNU", ntGNUABITag, sha1ID, 4)),
			sectionName: ".note.gnu.build-id",
		},
		{
			name:        "empty descriptor is ignored",
			elf:         elfWithSection(t, elf.ELFCLASS64, elf.SHT_NOTE, 4, encodeELFNote("GNU", ntGNUBuildID, nil, 4)),
			sectionName: ".note.gnu.build-id",
		},
		{
			name:        "truncated descriptor is ignored",
			elf:         elfWithSection(t, elf.ELFCLASS64, elf.SHT_NOTE, 4, encodeELFNote("GNU", ntGNUBuildID, sha1ID, 4)[:20]),
			sectionName: ".note.gnu.build-id",
		},
		{
			name: "no build-id section",
			elf:  elfWithDynamicSection(t, elf.ELFCLASS64, nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := elfutil.NewFile(bytes.NewReader(tt.elf))
			require.NoError(t, err)
			f.Sections[1].Name = tt.sectionName
			assert.Equal(t, tt.want, findELFIdentifiers(f))
		})
	}
}

type countingNoteReader struct {
	io.ReaderAt
	bytesRead int
}

func (r *countingNoteReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.ReaderAt.ReadAt(p, off)
	r.bytesRead += n
	return n, err
}

func Test_findELFIdentifiers_readLimit(t *testing.T) {
	id := encodeELFNote("GNU", ntGNUBuildID, []byte{0xde, 0xad, 0xbe, 0xef}, 4)
	data := append(id, make([]byte, maxELFNoteBytes)...)
	r := &countingNoteReader{ReaderAt: bytes.NewReader(elfWithSection(t, elf.ELFCLASS64, elf.SHT_NOTE, 4, data))}
	f, err := elfutil.NewFile(r)
	require.NoError(t, err)
	f.Sections[1].Name = ".note.gnu.build-id"
	r.bytesRead = 0

	assert.Equal(t, []file.ExecutableIdentifier{{Kind: file.ELFGNUBuildID, Value: "deadbeef"}}, findELFIdentifiers(f))
	assert.Equal(t, maxELFNoteBytes, r.bytesRead)
}

func Test_parseELFNotes_bigEndian(t *testing.T) {
	data := []byte{0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 3, 'G', 'N', 'U', 0, 0xde, 0xad, 0xbe, 0xef}
	assert.Equal(t, []elfNote{{owner: "GNU", typ: ntGNUBuildID, desc: data[16:]}}, parseELFNotes(data, 4, binary.BigEndian))
}

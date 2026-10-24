package executable

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
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
		write(elf.Section32{Type: uint32(elf.SHT_DYNAMIC), Off: uint32(dataOff), Size: uint32(len(dynamic)), Addralign: 1})
	} else {
		ehsize, shentsize := binary.Size(elf.Header64{}), binary.Size(elf.Section64{})
		dataOff := ehsize + 2*shentsize
		write(elf.Header64{
			Ident: ident, Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
			Shoff: uint64(ehsize), Ehsize: uint16(ehsize), Shentsize: uint16(shentsize), Shnum: 2,
		})
		write(elf.Section64{})
		write(elf.Section64{Type: uint32(elf.SHT_DYNAMIC), Off: uint64(dataOff), Size: uint64(len(dynamic)), Addralign: 1})
	}
	buf.Write(dynamic)
	return buf.Bytes()
}

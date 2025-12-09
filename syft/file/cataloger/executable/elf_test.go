package executable

import (
	"debug/elf"
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
		f, err := os.Open(filepath.Join("test-fixtures/elf", fixture))
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
		f, err := os.Open(filepath.Join("test-fixtures/shared-info", fixture))
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
		f, err := os.Open(filepath.Join("test-fixtures/shared-info", fixture))
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

func Test_elfNMSymbols_nonGoReturnsNil(t *testing.T) {
	// for non-Go binaries, elfNMSymbols should return nil since we only support Go for now
	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("test-fixtures/shared-info", fixture))
		require.NoError(t, err)
		return f
	}

	f, err := elf.NewFile(readerForFixture(t, "bin/hello_linux"))
	require.NoError(t, err)

	// no Go toolchain present
	toolchains := []file.Toolchain{}
	cfg := SymbolConfig{}

	symbols := elfNMSymbols(f, cfg, toolchains)
	assert.Nil(t, symbols, "expected nil symbols for non-Go binary")
}

func Test_elfGoToolchainDetection(t *testing.T) {
	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("test-fixtures/golang", fixture))
		require.NoError(t, err)
		return f
	}

	tests := []struct {
		name        string
		fixture     string
		wantPresent bool
	}{
		{
			name:        "go binary has toolchain",
			fixture:     "bin/hello_linux",
			wantPresent: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := readerForFixture(t, tt.fixture)
			f, err := elf.NewFile(reader)
			require.NoError(t, err)

			toolchains := elfToolchains(reader, f)
			assert.Equal(t, tt.wantPresent, isGoToolchainPresent(toolchains))

			if tt.wantPresent {
				require.NotEmpty(t, toolchains)
				assert.Equal(t, "go", toolchains[0].Name)
				assert.NotEmpty(t, toolchains[0].Version)
				assert.Equal(t, file.ToolchainKindCompiler, toolchains[0].Kind)
			}
		})
	}
}

func Test_elfGoSymbolCapture(t *testing.T) {
	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("test-fixtures/golang", fixture))
		require.NoError(t, err)
		return f
	}

	tests := []struct {
		name               string
		fixture            string
		cfg                GoSymbolConfig
		wantSymbols        []string // exact symbol names that must be present
		wantMinSymbolCount int
	}{
		{
			name:    "capture all symbol types",
			fixture: "bin/hello_linux",
			cfg: GoSymbolConfig{
				StandardLibrary:         true,
				ExtendedStandardLibrary: true,
				ThirdPartyModules:       true,
				ExportedSymbols:         true,
				UnexportedSymbols:       true,
			},
			wantSymbols: []string{
				// stdlib - fmt package (used via fmt.Println)
				"fmt.(*fmt).fmtInteger",
				"fmt.(*pp).doPrintf",
				// stdlib - strings package (used via strings.ToUpper)
				"strings.ToUpper",
				"strings.Map",
				// stdlib - encoding/json package (used via json.Marshal)
				"encoding/json.Marshal",
				// extended stdlib - golang.org/x/text (used via language.English)
				"golang.org/x/text/internal/language.Tag.String",
				"golang.org/x/text/internal/language.Language.String",
				// third-party - go-spew (used via spew.Dump)
				"github.com/davecgh/go-spew/spew.(*dumpState).dump",
				"github.com/davecgh/go-spew/spew.fdump",
			},
			wantMinSymbolCount: 50,
		},
		{
			name:    "capture only third-party symbols",
			fixture: "bin/hello_linux",
			cfg: GoSymbolConfig{
				ThirdPartyModules: true,
				ExportedSymbols:   true,
				UnexportedSymbols: true,
			},
			wantSymbols: []string{
				"github.com/davecgh/go-spew/spew.(*dumpState).dump",
				"github.com/davecgh/go-spew/spew.(*formatState).Format",
				"github.com/davecgh/go-spew/spew.fdump",
			},
		},
		{
			name:    "capture only extended stdlib symbols",
			fixture: "bin/hello_linux",
			cfg: GoSymbolConfig{
				ExtendedStandardLibrary: true,
				ExportedSymbols:         true,
				UnexportedSymbols:       true,
			},
			wantSymbols: []string{
				"golang.org/x/text/internal/language.Tag.String",
				"golang.org/x/text/internal/language.Parse",
			},
		},
		{
			name:    "capture with text section types only",
			fixture: "bin/hello_linux",
			cfg: GoSymbolConfig{
				Types:                   []string{"T", "t"}, // text section (code) symbols
				StandardLibrary:         true,
				ExtendedStandardLibrary: true,
				ThirdPartyModules:       true,
				ExportedSymbols:         true,
				UnexportedSymbols:       true,
			},
			wantSymbols: []string{
				"encoding/json.Marshal",
				"strings.ToUpper",
			},
			wantMinSymbolCount: 10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := readerForFixture(t, tt.fixture)
			f, err := elf.NewFile(reader)
			require.NoError(t, err)

			symbols := captureElfGoSymbols(f, SymbolConfig{Go: tt.cfg})
			symbolSet := make(map[string]struct{}, len(symbols))
			for _, sym := range symbols {
				symbolSet[sym] = struct{}{}
			}

			if tt.wantMinSymbolCount > 0 {
				assert.GreaterOrEqual(t, len(symbols), tt.wantMinSymbolCount,
					"expected at least %d symbols, got %d", tt.wantMinSymbolCount, len(symbols))
			}

			for _, want := range tt.wantSymbols {
				_, found := symbolSet[want]
				assert.True(t, found, "expected symbol %q to be present", want)
			}
		})
	}
}

func Test_elfNMSymbols_goReturnsSymbols(t *testing.T) {
	// for Go binaries, elfNMSymbols should return symbols when Go toolchain is present
	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("test-fixtures/golang", fixture))
		require.NoError(t, err)
		return f
	}

	reader := readerForFixture(t, "bin/hello_linux")
	f, err := elf.NewFile(reader)
	require.NoError(t, err)

	toolchains := []file.Toolchain{
		{Name: "go", Version: "1.24", Kind: file.ToolchainKindCompiler},
	}
	cfg := SymbolConfig{
		Go: GoSymbolConfig{
			Types:                   []string{"T", "t"},
			StandardLibrary:         true,
			ExtendedStandardLibrary: true,
			ThirdPartyModules:       true,
			ExportedSymbols:         true,
		},
	}

	symbols := elfNMSymbols(f, cfg, toolchains)
	assert.NotNil(t, symbols, "expected symbols for Go binary")
	assert.NotEmpty(t, symbols, "expected non-empty symbols for Go binary")
}

func Test_elfSymbolType(t *testing.T) {
	tests := []struct {
		name     string
		sym      elf.Symbol
		sections []*elf.Section
		want     string
	}{
		{
			name: "undefined symbol",
			sym: elf.Symbol{
				Info:    byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_NOTYPE),
				Section: elf.SHN_UNDEF,
			},
			want: "U",
		},
		{
			name: "absolute symbol global",
			sym: elf.Symbol{
				Info:    byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_NOTYPE),
				Section: elf.SHN_ABS,
			},
			want: "A",
		},
		{
			name: "absolute symbol local",
			sym: elf.Symbol{
				Info:    byte(elf.STB_LOCAL)<<4 | byte(elf.STT_NOTYPE),
				Section: elf.SHN_ABS,
			},
			want: "a",
		},
		{
			name: "common symbol",
			sym: elf.Symbol{
				Info:    byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT),
				Section: elf.SHN_COMMON,
			},
			want: "C",
		},
		{
			name: "weak undefined symbol",
			sym: elf.Symbol{
				Info:    byte(elf.STB_WEAK)<<4 | byte(elf.STT_NOTYPE),
				Section: elf.SHN_UNDEF,
			},
			want: "w",
		},
		{
			name: "weak undefined object",
			sym: elf.Symbol{
				Info:    byte(elf.STB_WEAK)<<4 | byte(elf.STT_OBJECT),
				Section: elf.SHN_UNDEF,
			},
			want: "v",
		},
		{
			name: "text section global",
			sym: elf.Symbol{
				Info:    byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC),
				Section: 1,
			},
			sections: []*elf.Section{
				{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}},                       // index 0: NULL section
				{SectionHeader: elf.SectionHeader{Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR}}, // index 1: .text
			},
			want: "T",
		},
		{
			name: "text section local",
			sym: elf.Symbol{
				Info:    byte(elf.STB_LOCAL)<<4 | byte(elf.STT_FUNC),
				Section: 1,
			},
			sections: []*elf.Section{
				{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}},                       // index 0: NULL section
				{SectionHeader: elf.SectionHeader{Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR}}, // index 1: .text
			},
			want: "t",
		},
		{
			name: "data section global",
			sym: elf.Symbol{
				Info:    byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT),
				Section: 1,
			},
			sections: []*elf.Section{
				{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}},                   // index 0: NULL section
				{SectionHeader: elf.SectionHeader{Flags: elf.SHF_ALLOC | elf.SHF_WRITE}}, // index 1: .data
			},
			want: "D",
		},
		{
			name: "bss section global",
			sym: elf.Symbol{
				Info:    byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT),
				Section: 1,
			},
			sections: []*elf.Section{
				{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}},                                         // index 0: NULL section
				{SectionHeader: elf.SectionHeader{Type: elf.SHT_NOBITS, Flags: elf.SHF_ALLOC | elf.SHF_WRITE}}, // index 1: .bss
			},
			want: "B",
		},
		{
			name: "rodata section global",
			sym: elf.Symbol{
				Info:    byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT),
				Section: 1,
			},
			sections: []*elf.Section{
				{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}},   // index 0: NULL section
				{SectionHeader: elf.SectionHeader{Flags: elf.SHF_ALLOC}}, // index 1: .rodata (no write flag = read-only)
			},
			want: "R",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := elfSymbolType(tt.sym, tt.sections)
			assert.Equal(t, tt.want, got)
		})
	}
}

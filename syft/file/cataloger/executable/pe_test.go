package executable

import (
	"debug/pe"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

func Test_peHasEntrypoint(t *testing.T) {

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
			fixture: "bin/hello.dll", // though this is a shared lib, it has an entrypoint (DLLMain)
			want:    false,
		},
		{
			name:    "application",
			fixture: "bin/hello.exe",
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := pe.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)
			assert.Equal(t, tt.want, peHasEntrypoint(f))
		})
	}
}

func Test_peHasExports(t *testing.T) {
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
			fixture: "bin/hello.dll",
			want:    true,
		},
		{
			name:    "application",
			fixture: "bin/hello.exe",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := pe.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)
			assert.Equal(t, tt.want, peHasExports(f))
		})
	}
}

func Test_peGoToolchainDetection(t *testing.T) {
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
			fixture:     "bin/hello.exe",
			wantPresent: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := readerForFixture(t, tt.fixture)

			toolchains := peToolchains(reader)
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

func Test_peGoSymbolCapture(t *testing.T) {
	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("test-fixtures/golang", fixture))
		require.NoError(t, err)
		return f
	}

	tests := []struct {
		name               string
		fixture            string
		cfg                SymbolConfig
		wantSymbols        []string // exact symbol names that must be present
		wantMinSymbolCount int
	}{
		{
			name:    "capture all symbol types",
			fixture: "bin/hello.exe",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					StandardLibrary:         true,
					ExtendedStandardLibrary: true,
					ThirdPartyModules:       true,
					ExportedSymbols:         true,
					UnexportedSymbols:       true,
				},
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
			fixture: "bin/hello.exe",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ThirdPartyModules: true,
					ExportedSymbols:   true,
					UnexportedSymbols: true,
				},
			},
			wantSymbols: []string{
				"github.com/davecgh/go-spew/spew.(*dumpState).dump",
				"github.com/davecgh/go-spew/spew.(*formatState).Format",
				"github.com/davecgh/go-spew/spew.fdump",
			},
		},
		{
			name:    "capture only extended stdlib symbols",
			fixture: "bin/hello.exe",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExtendedStandardLibrary: true,
					ExportedSymbols:         true,
					UnexportedSymbols:       true,
				},
			},
			wantSymbols: []string{
				"golang.org/x/text/internal/language.Tag.String",
				"golang.org/x/text/internal/language.Parse",
			},
		},
		{
			name:    "capture with text section types only",
			fixture: "bin/hello.exe",
			cfg: SymbolConfig{
				Types: []string{"T", "t"}, // text section (code) symbols
				Go: GoSymbolConfig{
					StandardLibrary:         true,
					ExtendedStandardLibrary: true,
					ThirdPartyModules:       true,
					ExportedSymbols:         true,
					UnexportedSymbols:       true,
				},
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
			f, err := pe.NewFile(reader)
			require.NoError(t, err)

			symbols := capturePeGoSymbols(f, tt.cfg)
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

func Test_peNMSymbols_goReturnsSymbols(t *testing.T) {
	// for Go binaries, peNMSymbols should return symbols when Go toolchain is present
	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("test-fixtures/golang", fixture))
		require.NoError(t, err)
		return f
	}

	reader := readerForFixture(t, "bin/hello.exe")
	f, err := pe.NewFile(reader)
	require.NoError(t, err)

	toolchains := []file.Toolchain{
		{Name: "go", Version: "1.24", Kind: file.ToolchainKindCompiler},
	}
	cfg := SymbolConfig{
		Types: []string{"T", "t"},
		Go: GoSymbolConfig{
			StandardLibrary:         true,
			ExtendedStandardLibrary: true,
			ThirdPartyModules:       true,
			ExportedSymbols:         true,
		},
	}

	symbols := peNMSymbols(f, cfg, toolchains)
	assert.NotNil(t, symbols, "expected symbols for Go binary")
	assert.NotEmpty(t, symbols, "expected non-empty symbols for Go binary")
}

func Test_peSymbolType(t *testing.T) {
	// create minimal sections for testing
	textSection := &pe.Section{SectionHeader: pe.SectionHeader{Characteristics: peSectionCntCode | peSectionMemExecute | peSectionMemRead}}
	dataSection := &pe.Section{SectionHeader: pe.SectionHeader{Characteristics: peSectionCntInitializedData | peSectionMemRead | peSectionMemWrite}}
	rdataSection := &pe.Section{SectionHeader: pe.SectionHeader{Characteristics: peSectionCntInitializedData | peSectionMemRead}}
	bssSection := &pe.Section{SectionHeader: pe.SectionHeader{Characteristics: peSectionCntUninitializedData | peSectionMemRead | peSectionMemWrite}}

	tests := []struct {
		name     string
		sym      *pe.Symbol
		sections []*pe.Section
		want     string
	}{
		{
			name: "undefined symbol",
			sym: &pe.Symbol{
				SectionNumber: 0,
				StorageClass:  peSymClassExternal,
			},
			want: "U",
		},
		{
			name: "absolute symbol external",
			sym: &pe.Symbol{
				SectionNumber: -1,
				StorageClass:  peSymClassExternal,
			},
			want: "A",
		},
		{
			name: "absolute symbol static",
			sym: &pe.Symbol{
				SectionNumber: -1,
				StorageClass:  peSymClassStatic,
			},
			want: "a",
		},
		{
			name: "debug symbol",
			sym: &pe.Symbol{
				SectionNumber: -2,
				StorageClass:  peSymClassExternal,
			},
			want: "-",
		},
		{
			name: "text section external",
			sym: &pe.Symbol{
				SectionNumber: 1,
				StorageClass:  peSymClassExternal,
			},
			sections: []*pe.Section{textSection},
			want:     "T",
		},
		{
			name: "text section static",
			sym: &pe.Symbol{
				SectionNumber: 1,
				StorageClass:  peSymClassStatic,
			},
			sections: []*pe.Section{textSection},
			want:     "t",
		},
		{
			name: "data section external",
			sym: &pe.Symbol{
				SectionNumber: 1,
				StorageClass:  peSymClassExternal,
			},
			sections: []*pe.Section{dataSection},
			want:     "D",
		},
		{
			name: "data section static",
			sym: &pe.Symbol{
				SectionNumber: 1,
				StorageClass:  peSymClassStatic,
			},
			sections: []*pe.Section{dataSection},
			want:     "d",
		},
		{
			name: "rodata section external",
			sym: &pe.Symbol{
				SectionNumber: 1,
				StorageClass:  peSymClassExternal,
			},
			sections: []*pe.Section{rdataSection},
			want:     "R",
		},
		{
			name: "bss section external",
			sym: &pe.Symbol{
				SectionNumber: 1,
				StorageClass:  peSymClassExternal,
			},
			sections: []*pe.Section{bssSection},
			want:     "B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peSymbolType(tt.sym, tt.sections)
			assert.Equal(t, tt.want, got)
		})
	}
}

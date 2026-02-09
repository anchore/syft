package executable

import (
	"debug/macho"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

func Test_machoHasEntrypoint(t *testing.T) {

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
			fixture: "bin/libhello.dylib",
			want:    false,
		},
		{
			name:    "application",
			fixture: "bin/hello_mac",
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := macho.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)
			assert.Equal(t, tt.want, machoHasEntrypoint(f))
		})
	}
}

func Test_machoHasExports(t *testing.T) {
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
			fixture: "bin/libhello.dylib",
			want:    true,
		},
		{
			name:    "application",
			fixture: "bin/hello_mac",
			want:    false,
		},
		{
			name:    "gcc-amd64-darwin-exec-debug",
			fixture: "bin/gcc-amd64-darwin-exec-debug",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := macho.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)
			assert.Equal(t, tt.want, machoHasExports(f))
		})
	}
}

func Test_machoUniversal(t *testing.T) {
	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("test-fixtures/shared-info", fixture))
		require.NoError(t, err)
		return f
	}

	tests := []struct {
		name    string
		fixture string
		want    file.Executable
	}{
		{
			name:    "universal lib",
			fixture: "bin/libhello_universal.dylib",
			want:    file.Executable{HasExports: true, HasEntrypoint: false},
		},
		{
			name:    "universal application",
			fixture: "bin/hello_mac_universal",
			want:    file.Executable{HasExports: false, HasEntrypoint: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data file.Executable
			err := findMachoFeatures(&data, readerForFixture(t, tt.fixture), SymbolConfig{})
			require.NoError(t, err)

			assert.Equal(t, tt.want.HasEntrypoint, data.HasEntrypoint)
			assert.Equal(t, tt.want.HasExports, data.HasExports)
		})
	}
}

func Test_machoGoToolchainDetection(t *testing.T) {
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
			fixture:     "bin/hello_mac",
			wantPresent: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := readerForFixture(t, tt.fixture)

			toolchains := machoToolchains(reader)
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

func Test_machoGoSymbolCapture(t *testing.T) {
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
			fixture: "bin/hello_mac",
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
			fixture: "bin/hello_mac",
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
			fixture: "bin/hello_mac",
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
			fixture: "bin/hello_mac",
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
			f, err := macho.NewFile(reader)
			require.NoError(t, err)

			symbols := captureMachoGoSymbols(f, tt.cfg)
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

func Test_machoNMSymbols_goReturnsSymbols(t *testing.T) {
	// for Go binaries, machoNMSymbols should return symbols when Go toolchain is present
	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("test-fixtures/golang", fixture))
		require.NoError(t, err)
		return f
	}

	reader := readerForFixture(t, "bin/hello_mac")
	f, err := macho.NewFile(reader)
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

	symbols := machoNMSymbols(f, cfg, toolchains)
	assert.NotNil(t, symbols, "expected symbols for Go binary")
	assert.NotEmpty(t, symbols, "expected non-empty symbols for Go binary")
}

func Test_machoSymbolType(t *testing.T) {
	// create minimal sections for testing
	textSection := &macho.Section{SectionHeader: macho.SectionHeader{Seg: "__TEXT"}}
	dataSection := &macho.Section{SectionHeader: macho.SectionHeader{Seg: "__DATA"}}
	bssSection := &macho.Section{SectionHeader: macho.SectionHeader{Seg: "__DATA", Name: "__bss"}}

	tests := []struct {
		name     string
		sym      macho.Symbol
		sections []*macho.Section
		want     string
	}{
		{
			name: "undefined external symbol",
			sym: macho.Symbol{
				Type: machoNExt, // external, undefined (N_TYPE = 0 = N_UNDF)
			},
			want: "U",
		},
		{
			name: "absolute external symbol",
			sym: macho.Symbol{
				Type: machoNExt | machoNAbs, // external, absolute
			},
			want: "A",
		},
		{
			name: "absolute local symbol",
			sym: macho.Symbol{
				Type: machoNAbs, // local, absolute
			},
			want: "a",
		},
		{
			name: "text section external",
			sym: macho.Symbol{
				Type: machoNExt | machoNSect, // external, section-defined
				Sect: 1,
			},
			sections: []*macho.Section{textSection},
			want:     "T",
		},
		{
			name: "text section local",
			sym: macho.Symbol{
				Type: machoNSect, // local, section-defined
				Sect: 1,
			},
			sections: []*macho.Section{textSection},
			want:     "t",
		},
		{
			name: "data section external",
			sym: macho.Symbol{
				Type: machoNExt | machoNSect,
				Sect: 1,
			},
			sections: []*macho.Section{dataSection},
			want:     "D",
		},
		{
			name: "bss section external",
			sym: macho.Symbol{
				Type: machoNExt | machoNSect,
				Sect: 1,
			},
			sections: []*macho.Section{bssSection},
			want:     "B",
		},
		{
			name: "stab debugging symbol",
			sym: macho.Symbol{
				Type: machoNStab, // any stab symbol
			},
			want: "-",
		},
		{
			name: "indirect symbol",
			sym: macho.Symbol{
				Type: machoNExt | machoNIndr,
			},
			want: "I",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := machoSymbolType(tt.sym, tt.sections)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_isGoToolchainPresent(t *testing.T) {
	tests := []struct {
		name       string
		toolchains []file.Toolchain
		want       bool
	}{
		{
			name:       "empty toolchains",
			toolchains: []file.Toolchain{},
			want:       false,
		},
		{
			name: "go toolchain present",
			toolchains: []file.Toolchain{
				{Name: "go", Version: "1.21.0", Kind: file.ToolchainKindCompiler},
			},
			want: true,
		},
		{
			name: "other toolchain only",
			toolchains: []file.Toolchain{
				{Name: "gcc", Version: "12.0", Kind: file.ToolchainKindCompiler},
			},
			want: false,
		},
		{
			name: "go among multiple toolchains",
			toolchains: []file.Toolchain{
				{Name: "gcc", Version: "12.0", Kind: file.ToolchainKindCompiler},
				{Name: "go", Version: "1.21.0", Kind: file.ToolchainKindCompiler},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGoToolchainPresent(tt.toolchains)
			assert.Equal(t, tt.want, got)
		})
	}
}

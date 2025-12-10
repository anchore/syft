package executable

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func TestShouldCaptureSymbols(t *testing.T) {
	tests := []struct {
		name string
		data *file.Executable
		cfg  SymbolConfig
		want bool
	}{
		{
			name: "nil data returns false",
			data: nil,
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
			},
			want: false,
		},
		{
			name: "empty capture scope returns false",
			data: &file.Executable{},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{},
			},
			want: false,
		},
		{
			name: "scope golang with go toolchain returns true",
			data: &file.Executable{
				Toolchains: []file.Toolchain{
					{Name: "go", Version: "1.21.0", Kind: file.ToolchainKindCompiler},
				},
			},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
			},
			want: true,
		},
		{
			name: "scope golang without go toolchain returns false",
			data: &file.Executable{
				Toolchains: []file.Toolchain{
					{Name: "gcc", Version: "12.0.0", Kind: file.ToolchainKindCompiler},
				},
			},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
			},
			want: false,
		},
		{
			name: "scope golang with empty toolchains returns false",
			data: &file.Executable{},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
			},
			want: false,
		},
		{
			name: "go toolchain among multiple toolchains returns true",
			data: &file.Executable{
				Toolchains: []file.Toolchain{
					{Name: "gcc", Version: "12.0.0", Kind: file.ToolchainKindCompiler},
					{Name: "go", Version: "1.21.0", Kind: file.ToolchainKindCompiler},
				},
			},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldCaptureSymbols(tt.data, tt.cfg)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestHasGolangToolchain(t *testing.T) {
	tests := []struct {
		name string
		data *file.Executable
		want bool
	}{
		{
			name: "empty toolchains",
			data: &file.Executable{},
			want: false,
		},
		{
			name: "no go toolchain",
			data: &file.Executable{
				Toolchains: []file.Toolchain{
					{Name: "gcc", Version: "12.0.0", Kind: file.ToolchainKindCompiler},
					{Name: "clang", Version: "15.0.0", Kind: file.ToolchainKindCompiler},
				},
			},
			want: false,
		},
		{
			name: "has go toolchain",
			data: &file.Executable{
				Toolchains: []file.Toolchain{
					{Name: "go", Version: "1.21.0", Kind: file.ToolchainKindCompiler},
				},
			},
			want: true,
		},
		{
			name: "go toolchain among others",
			data: &file.Executable{
				Toolchains: []file.Toolchain{
					{Name: "gcc", Version: "12.0.0", Kind: file.ToolchainKindCompiler},
					{Name: "go", Version: "1.21.0", Kind: file.ToolchainKindCompiler},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasGolangToolchain(tt.data)
			require.Equal(t, tt.want, got)
		})
	}
}

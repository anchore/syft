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
				CaptureScope: []SymbolCaptureScope{SymbolScopeAll},
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
			name: "scope none returns false",
			data: &file.Executable{},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeNone},
			},
			want: false,
		},
		{
			name: "scope all returns true",
			data: &file.Executable{},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeAll},
			},
			want: true,
		},
		{
			name: "scope libraries with exports returns true",
			data: &file.Executable{
				HasExports: true,
			},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeLibraries},
			},
			want: true,
		},
		{
			name: "scope libraries without exports returns false",
			data: &file.Executable{
				HasExports: false,
			},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeLibraries},
			},
			want: false,
		},
		{
			name: "scope applications with entrypoint returns true",
			data: &file.Executable{
				HasEntrypoint: true,
			},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeApplications},
			},
			want: true,
		},
		{
			name: "scope applications without entrypoint returns false",
			data: &file.Executable{
				HasEntrypoint: false,
			},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeApplications},
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
			name: "multiple scopes with one match returns true",
			data: &file.Executable{
				HasExports:    false,
				HasEntrypoint: true,
			},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeLibraries, SymbolScopeApplications},
			},
			want: true,
		},
		{
			name: "multiple scopes with no match returns false",
			data: &file.Executable{
				HasExports:    false,
				HasEntrypoint: false,
			},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeLibraries, SymbolScopeApplications},
			},
			want: false,
		},
		{
			name: "none scope followed by matching scope returns true",
			data: &file.Executable{
				HasEntrypoint: true,
			},
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeNone, SymbolScopeApplications},
			},
			want: true,
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
					{Name: "ld", Version: "2.38", Kind: file.ToolchainKindLinker},
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

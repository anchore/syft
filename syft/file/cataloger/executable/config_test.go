package executable

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func TestDefaultConfig_SymbolCaptureIsDisabled(t *testing.T) {
	// symbol capture should be disabled by default -- this is an expensive operation space-wise in the SBOM
	// and should only be enabled when explicitly configured by the user.
	cfg := DefaultConfig()

	require.Empty(t, cfg.Symbols.CaptureScope, "symbol capture should be disabled by default (empty capture scope)")

	// verify that shouldCaptureSymbols returns false for any executable when using default config
	assert.False(t, shouldCaptureSymbols(nil, cfg.Symbols), "should not capture symbols for nil executable")
	assert.False(t, shouldCaptureSymbols(&file.Executable{}, cfg.Symbols), "should not capture symbols for empty executable")
	assert.False(t, shouldCaptureSymbols(&file.Executable{
		Toolchains: []file.Toolchain{
			{Name: "go", Version: "1.21.0", Kind: file.ToolchainKindCompiler},
		},
	}, cfg.Symbols), "should not capture symbols even for go binaries when using default config")
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "default config is valid",
			cfg:     DefaultConfig(),
			wantErr: require.NoError,
		},
		{
			name: "valid config with golang scope enabled",
			cfg: Config{
				Symbols: SymbolConfig{
					CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
					Go: GoSymbolConfig{
						ExportedSymbols:   true,
						ThirdPartyModules: true,
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name: "empty capture scope with Go settings is valid",
			cfg: Config{
				Symbols: SymbolConfig{
					CaptureScope: []SymbolCaptureScope{},
					Go: GoSymbolConfig{
						ExportedSymbols:   true,
						ThirdPartyModules: true,
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name: "invalid capture scope",
			cfg: Config{
				Symbols: SymbolConfig{
					CaptureScope: []SymbolCaptureScope{"invalid-scope"},
				},
			},
			wantErr: require.Error,
		},
		{
			name: "invalid NM type",
			cfg: Config{
				Symbols: SymbolConfig{
					Types: []string{"X", "Y"},
				},
			},
			wantErr: require.Error,
		},
		{
			name: "valid NM types",
			cfg: Config{
				Symbols: SymbolConfig{
					Types: []string{"T", "t", "R"},
				},
			},
			wantErr: require.NoError,
		},
		{
			name: "both exported and unexported disabled with golang scope",
			cfg: Config{
				Symbols: SymbolConfig{
					CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
					Go: GoSymbolConfig{
						ExportedSymbols:   false,
						UnexportedSymbols: false,
						ThirdPartyModules: true,
					},
				},
			},
			wantErr: require.Error,
		},
		{
			name: "both exported and unexported disabled without golang scope is valid",
			cfg: Config{
				Symbols: SymbolConfig{
					CaptureScope: []SymbolCaptureScope{},
					Go: GoSymbolConfig{
						ExportedSymbols:   false,
						UnexportedSymbols: false,
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name: "all module sources disabled with golang scope",
			cfg: Config{
				Symbols: SymbolConfig{
					CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
					Go: GoSymbolConfig{
						ExportedSymbols:         true,
						StandardLibrary:         false,
						ExtendedStandardLibrary: false,
						ThirdPartyModules:       false,
					},
				},
			},
			wantErr: require.Error,
		},
		{
			name: "all module sources disabled without golang scope is valid",
			cfg: Config{
				Symbols: SymbolConfig{
					CaptureScope: []SymbolCaptureScope{},
					Go: GoSymbolConfig{
						ExportedSymbols:         true,
						StandardLibrary:         false,
						ExtendedStandardLibrary: false,
						ThirdPartyModules:       false,
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name: "only standard library enabled is valid",
			cfg: Config{
				Symbols: SymbolConfig{
					CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
					Go: GoSymbolConfig{
						ExportedSymbols:         true,
						StandardLibrary:         true,
						ExtendedStandardLibrary: false,
						ThirdPartyModules:       false,
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name: "only extended stdlib enabled is valid",
			cfg: Config{
				Symbols: SymbolConfig{
					CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
					Go: GoSymbolConfig{
						ExportedSymbols:         true,
						StandardLibrary:         false,
						ExtendedStandardLibrary: true,
						ThirdPartyModules:       false,
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name: "only third party modules enabled is valid",
			cfg: Config{
				Symbols: SymbolConfig{
					CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
					Go: GoSymbolConfig{
						ExportedSymbols:         true,
						StandardLibrary:         false,
						ExtendedStandardLibrary: false,
						ThirdPartyModules:       true,
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name: "only unexported symbols enabled is valid",
			cfg: Config{
				Symbols: SymbolConfig{
					CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
					Go: GoSymbolConfig{
						ExportedSymbols:   false,
						UnexportedSymbols: true,
						ThirdPartyModules: true,
					},
				},
			},
			wantErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			tt.wantErr(t, err)
		})
	}
}

func TestSymbolConfig_Validate_ErrorMessages(t *testing.T) {
	tests := []struct {
		name           string
		cfg            SymbolConfig
		wantErrContain string
	}{
		{
			name: "invalid capture scope error message",
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{"rust"},
			},
			wantErrContain: "invalid symbol capture scope",
		},
		{
			name: "invalid NM type error message",
			cfg: SymbolConfig{
				Types: []string{"Z"},
			},
			wantErrContain: "invalid NM type",
		},
		{
			name: "both export options disabled error message",
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
				Go: GoSymbolConfig{
					ExportedSymbols:   false,
					UnexportedSymbols: false,
					ThirdPartyModules: true,
				},
			},
			wantErrContain: "both exported-symbols and unexported-symbols are disabled",
		},
		{
			name: "all module sources disabled error message",
			cfg: SymbolConfig{
				CaptureScope: []SymbolCaptureScope{SymbolScopeGolang},
				Go: GoSymbolConfig{
					ExportedSymbols:         true,
					StandardLibrary:         false,
					ExtendedStandardLibrary: false,
					ThirdPartyModules:       false,
				},
			},
			wantErrContain: "all module sources",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrContain)
		})
	}
}

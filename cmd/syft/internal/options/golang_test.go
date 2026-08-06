package options

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cataloging"
)

func Test_golangConfig_PostLoad(t *testing.T) {
	tests := []struct {
		name            string
		cfg             golangConfig
		expected        cataloging.SymbolScope
		expectedInclude []string
		wantErr         assert.ErrorAssertionFunc
	}{
		{
			name:     "normalize all",
			cfg:      golangConfig{CaptureSymbols: "all"},
			expected: cataloging.SymbolScopeAll,
		},
		{
			name:     "normalize stdlib",
			cfg:      golangConfig{CaptureSymbols: "stdlib"},
			expected: cataloging.SymbolScopeStdlib,
		},
		{
			name:     "normalize extended-stdlib",
			cfg:      golangConfig{CaptureSymbols: " Extended-Stdlib "},
			expected: cataloging.SymbolScopeExtendedStdlib,
		},
		{
			name: "include patterns keep embedded commas",
			cfg: golangConfig{
				CaptureSymbols: "stdlib",
				// brace alternation contains a comma; splitting on it would corrupt the pattern
				CaptureSymbolsInclude: []string{"github.com/{foo,bar}/**", "golang.org/x/**"},
			},
			expected:        cataloging.SymbolScopeStdlib,
			expectedInclude: []string{"github.com/{foo,bar}/**", "golang.org/x/**"},
		},
		{
			// viper splits a comma-separated scalar (env var or bare yaml string) but does not trim,
			// so a leading space would otherwise survive into a pattern that silently matches nothing
			name: "include patterns are trimmed",
			cfg: golangConfig{
				CaptureSymbols:        "stdlib",
				CaptureSymbolsInclude: []string{"golang.org/x/**", " github.com/foo/** "},
			},
			expected:        cataloging.SymbolScopeStdlib,
			expectedInclude: []string{"golang.org/x/**", "github.com/foo/**"},
		},
		{
			name:     "empty defaults to none",
			cfg:      golangConfig{CaptureSymbols: ""},
			expected: cataloging.SymbolScopeNone,
		},
		{
			name:     "invalid value defaults to none",
			cfg:      golangConfig{CaptureSymbols: "stdlbi"},
			expected: cataloging.SymbolScopeNone,
		},
		{
			name:     "boolean spellings default to none",
			cfg:      golangConfig{CaptureSymbols: "true"},
			expected: cataloging.SymbolScopeNone,
		},
		{
			name:     "explicit none resolves to none",
			cfg:      golangConfig{CaptureSymbols: "none"},
			expected: cataloging.SymbolScopeNone,
		},
		{
			name:     "explicit none is not case sensitive",
			cfg:      golangConfig{CaptureSymbols: " NONE "},
			expected: cataloging.SymbolScopeNone,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			err := tt.cfg.PostLoad()
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tt.expected, tt.cfg.CaptureSymbols)
			assert.Equal(t, tt.expectedInclude, tt.cfg.CaptureSymbolsInclude)
		})
	}
}

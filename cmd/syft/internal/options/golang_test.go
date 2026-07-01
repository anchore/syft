package options

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cataloging"
)

func Test_golangConfig_PostLoad(t *testing.T) {
	tests := []struct {
		name     string
		cfg      golangConfig
		expected cataloging.SymbolScope
		wantErr  assert.ErrorAssertionFunc
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
			name:     "empty defaults to none",
			cfg:      golangConfig{CaptureSymbols: ""},
			expected: cataloging.SymbolScopeNone,
		},
		{
			name:    "error on invalid value",
			cfg:     golangConfig{CaptureSymbols: "bogus"},
			wantErr: assert.Error,
		},
		{
			name:    "boolean spellings are not valid",
			cfg:     golangConfig{CaptureSymbols: "true"},
			wantErr: assert.Error,
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
		})
	}
}

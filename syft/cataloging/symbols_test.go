package cataloging

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_SymbolScope_Parse(t *testing.T) {
	tests := []struct {
		input    string
		expected SymbolScope
	}{
		{"all", SymbolScopeAll},
		{"ALL", SymbolScopeAll},
		{"  all  ", SymbolScopeAll},
		{"stdlib", SymbolScopeStdlib},
		{"Stdlib", SymbolScopeStdlib},
		{"none", SymbolScopeNone},
		{"", SymbolScopeNone},
		{"true", SymbolScopeNone},
		{"false", SymbolScopeNone},
		{"bogus", SymbolScopeNone},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			assert.Equal(t, test.expected, SymbolScope(test.input).Parse())
		})
	}
}

package golang

import (
	"os"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_moduleSymbols(t *testing.T) {
	mainModule := &debug.Module{Path: "github.com/someorg/somecli"}
	deps := []*debug.Module{
		{Path: "github.com/foo/bar"},
		{Path: "github.com/foo/bar/v2"},
		nil,
	}

	tests := []struct {
		name           string
		symbols        []binarySymbol
		expected       map[string][]string
		expectedStdlib []string
	}{
		{
			name:     "no symbols",
			symbols:  nil,
			expected: nil,
		},
		{
			name: "attribute symbols by longest module path prefix",
			symbols: []binarySymbol{
				{packagePath: "github.com/foo/bar", name: "github.com/foo/bar.Parse"},
				{packagePath: "github.com/foo/bar/internal/util", name: "github.com/foo/bar/internal/util.(*Helper).Do"},
				{packagePath: "github.com/foo/bar/v2", name: "github.com/foo/bar/v2.Parse"},
			},
			expected: map[string][]string{
				"github.com/foo/bar": {
					"github.com/foo/bar.Parse",
					"github.com/foo/bar/internal/util.(*Helper).Do",
				},
				"github.com/foo/bar/v2": {
					"github.com/foo/bar/v2.Parse",
				},
			},
		},
		{
			name: "main package symbols are attributed to the main module",
			symbols: []binarySymbol{
				{packagePath: "main", name: "main.main"},
				{packagePath: "github.com/someorg/somecli/cmd", name: "github.com/someorg/somecli/cmd.Execute"},
			},
			expected: map[string][]string{
				"github.com/someorg/somecli": {
					"github.com/someorg/somecli/cmd.Execute",
					"main.main",
				},
			},
		},
		{
			name: "stdlib and runtime symbols are collected separately",
			symbols: []binarySymbol{
				{packagePath: "runtime", name: "runtime.main"},
				{packagePath: "net/http", name: "net/http.(*Client).Do"},
				{packagePath: "internal/abi", name: "internal/abi.(*Type).Kind"},
			},
			expected: map[string][]string{},
			expectedStdlib: []string{
				"internal/abi.(*Type).Kind",
				"net/http.(*Client).Do",
				"runtime.main",
			},
		},
		{
			name: "duplicate symbols are deduplicated",
			symbols: []binarySymbol{
				{packagePath: "github.com/foo/bar", name: "github.com/foo/bar.Parse"},
				{packagePath: "github.com/foo/bar", name: "github.com/foo/bar.Parse"},
			},
			expected: map[string][]string{
				"github.com/foo/bar": {
					"github.com/foo/bar.Parse",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotByModule, gotStdlib := moduleSymbols(tt.symbols, mainModule, deps)
			assert.Equal(t, tt.expected, gotByModule)
			assert.Equal(t, tt.expectedStdlib, gotStdlib)
		})
	}
}

func Test_getSymbols(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PE binaries are not supported for symbol extraction")
	}

	// the test executable is itself a go binary with a pclntab, which makes for a hermetic fixture
	exe, err := os.Executable()
	require.NoError(t, err)

	f, err := os.Open(exe)
	require.NoError(t, err)
	defer f.Close()

	symbols, err := getSymbols(f)
	require.NoError(t, err)
	require.NotEmpty(t, symbols)

	var foundRuntime, foundTesting bool
	for _, sym := range symbols {
		switch {
		case sym.packagePath == "runtime" && sym.name == "runtime.main":
			foundRuntime = true
		case sym.packagePath == "testing" && sym.name == "testing.tRunner":
			foundTesting = true
		}
	}
	assert.True(t, foundRuntime, "expected to find runtime.main symbol")
	assert.True(t, foundTesting, "expected to find testing.tRunner symbol")
}

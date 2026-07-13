package golang

import (
	"debug/gosym"
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
		expected       map[string]map[string][]string
		expectedStdlib map[string][]string
	}{
		{
			name:     "no symbols",
			symbols:  nil,
			expected: nil,
		},
		{
			name: "attribute symbols by longest module path prefix, grouped by import path",
			symbols: []binarySymbol{
				{packagePath: "github.com/foo/bar", name: "github.com/foo/bar.Parse"},
				{packagePath: "github.com/foo/bar/internal/util", name: "github.com/foo/bar/internal/util.(*Helper).Do"},
				{packagePath: "github.com/foo/bar/v2", name: "github.com/foo/bar/v2.Parse"},
			},
			expected: map[string]map[string][]string{
				"github.com/foo/bar": {
					"github.com/foo/bar":               {"Parse"},
					"github.com/foo/bar/internal/util": {"(*Helper).Do"},
				},
				"github.com/foo/bar/v2": {
					"github.com/foo/bar/v2": {"Parse"},
				},
			},
		},
		{
			name: "main package symbols are attributed to the main module and keyed by the main import path",
			symbols: []binarySymbol{
				{packagePath: "main", name: "main.main"},
				{packagePath: "github.com/someorg/somecli/cmd", name: "github.com/someorg/somecli/cmd.Execute"},
			},
			expected: map[string]map[string][]string{
				"github.com/someorg/somecli": {
					"github.com/someorg/somecli/cmd": {"Execute"},
					"main":                           {"main"},
				},
			},
		},
		{
			name: "stdlib and runtime symbols are collected separately, grouped by import path",
			symbols: []binarySymbol{
				{packagePath: "runtime", name: "runtime.main"},
				{packagePath: "net/http", name: "net/http.(*Client).Do"},
				{packagePath: "internal/abi", name: "internal/abi.(*Type).Kind"},
			},
			expected: map[string]map[string][]string{},
			expectedStdlib: map[string][]string{
				"internal/abi": {"(*Type).Kind"},
				"net/http":     {"(*Client).Do"},
				"runtime":      {"main"},
			},
		},
		{
			name: "duplicate symbols are deduplicated",
			symbols: []binarySymbol{
				{packagePath: "github.com/foo/bar", name: "github.com/foo/bar.Parse"},
				{packagePath: "github.com/foo/bar", name: "github.com/foo/bar.Parse"},
			},
			expected: map[string]map[string][]string{
				"github.com/foo/bar": {
					"github.com/foo/bar": {"Parse"},
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

func Test_localSymbolName(t *testing.T) {
	tests := []struct {
		name       string
		symbol     string
		importPath string
		expected   string
	}{
		{
			name:       "function",
			symbol:     "github.com/foo/bar.Parse",
			importPath: "github.com/foo/bar",
			expected:   "Parse",
		},
		{
			name:       "pointer-receiver method",
			symbol:     "github.com/foo/bar.(*T).M",
			importPath: "github.com/foo/bar",
			expected:   "(*T).M",
		},
		{
			// type-argument brackets sit to the right of the stripped prefix and must be preserved
			name:       "generic instantiation",
			symbol:     "github.com/foo/bar.Do[net/url.Values]",
			importPath: "github.com/foo/bar",
			expected:   "Do[net/url.Values]",
		},
		{
			// a sibling package must not be stripped by a shorter import path (the "." boundary guards this)
			name:       "prefix mismatch is returned unchanged",
			symbol:     "github.com/foo/bar/sub.Func",
			importPath: "github.com/foo/bar",
			expected:   "github.com/foo/bar/sub.Func",
		},
		{
			name:       "empty import path is returned unchanged",
			symbol:     "runtime.main",
			importPath: "",
			expected:   "runtime.main",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, localSymbolName(tt.symbol, tt.importPath))
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

	// the recovery loop relies on packagePathFromSymbolName, so confirm at least one recovered name is
	// present that debug/gosym's table.Funcs does not surface directly (i.e. an inlined function).
	require.True(t, hasInlinedOnlySymbol(t, exe, symbols), "expected to recover at least one inlined-only symbol")
}

// hasInlinedOnlySymbol reports whether syms contains a function name that is absent from the raw
// debug/gosym function table for the same binary — i.e. a name that could only have come from the
// funcname-table recovery path.
func hasInlinedOnlySymbol(t *testing.T, exe string, syms []binarySymbol) bool {
	t.Helper()

	f, err := os.Open(exe)
	require.NoError(t, err)
	defer f.Close()

	pclntab, textStart, err := readPclntab(f)
	require.NoError(t, err)

	table, err := gosym.NewTable(nil, gosym.NewLineTable(pclntab, textStart))
	require.NoError(t, err)

	gosymNames := make(map[string]struct{}, len(table.Funcs))
	for _, fn := range table.Funcs {
		gosymNames[fn.Name] = struct{}{}
	}

	for _, sym := range syms {
		if _, ok := gosymNames[sym.name]; !ok {
			return true
		}
	}
	return false
}

func Test_packagePathFromSymbolName(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"path/filepath.IsLocal", "path/filepath"},
		// pointer-receiver method
		{"golang.org/x/net/html.(*Tokenizer).Next", "golang.org/x/net/html"},
		// versioned (major-version-suffixed) module path
		{"github.com/foo/bar/v2.Parse", "github.com/foo/bar/v2"},
		{"github.com/foo/bar/v2.(*Client).Do", "github.com/foo/bar/v2"},
		{"github.com/foo/bar.Parse.func1", "github.com/foo/bar"},
		{"main.main", "main"},
		{"runtime.gcBgMarkWorker", "runtime"},
		// generic instantiations: type arguments must not corrupt the package path
		{"foo/bar.Do[net/url.Values]", "foo/bar"},
		{"github.com/foo/bar.Map[go.shape.int,go.shape.string]", "github.com/foo/bar"},
		{"main.Do[go.shape.int]", "main"},
		// no package-qualifying dot
		{"runtime", ""},
		// compiler/linker-generated symbols belong to no package
		{"type:.eq.[]string", ""},
		{"type..hash.runtime._type", ""},
		{"go:string.\"foo\"", ""},
		// pre-go1.20 toolchains generated symbols with "." where newer ones use ":"
		{"go.buildid", ""},
		{"go.type.*runtime._type", ""},
		{"go.itab.*os.File,io.Reader", ""},
		{"go.string.\"foo\"", ""},
		// module paths that begin with "go." are not compiler-generated
		{"go.uber.org/zap.(*Logger).Info", "go.uber.org/zap"},
		{"go.opentelemetry.io/otel.Tracer", "go.opentelemetry.io/otel"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, packagePathFromSymbolName(test.name))
		})
	}
}

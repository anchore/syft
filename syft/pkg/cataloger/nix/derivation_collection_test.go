package nix

import (
	"testing"

	"github.com/nix-community/go-nix/pkg/derivation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDerivationCollection_Add(t *testing.T) {
	c := newDerivationCollection()

	d := &derivation.Derivation{
		Outputs: map[string]*derivation.Output{
			"out": {
				Path: "/nix/store/abc123-foo",
			},
			"dev": {
				Path: "/nix/store/def456-foo-dev",
			},
		},
	}

	c.add("/nix/store/xyz789-foo.drv", d)

	assert.Len(t, c.derivationsByDrvPath, 1)
	assert.Len(t, c.drvPathByOutputPath, 2)
	assert.Equal(t, "/nix/store/xyz789-foo.drv", c.drvPathByOutputPath["/nix/store/abc123-foo"])
	assert.Equal(t, "/nix/store/xyz789-foo.drv", c.drvPathByOutputPath["/nix/store/def456-foo-dev"])
}

func TestDerivationCollection_AddNilDerivation(t *testing.T) {
	c := newDerivationCollection()
	c.add("/nix/store/xyz789-foo.drv", nil)

	assert.Empty(t, c.derivationsByDrvPath)
	assert.Empty(t, c.drvPathByOutputPath)
}

func TestDerivationCollection_FindDerivationForOutput(t *testing.T) {
	tests := []struct {
		name       string
		outputPath string
		expected   string
	}{
		{
			name:       "output path exists",
			outputPath: "/nix/store/abc123-foo",
			expected:   "xyz789-foo.drv",
		},
		{
			name:       "output path exists without leading slash",
			outputPath: "nix/store/abc123-foo",
			expected:   "xyz789-foo.drv",
		},
		{
			name:       "output path does not exist",
			outputPath: "/nix/store/nonexistent",
			expected:   "",
		},
	}

	c := newDerivationCollection()
	d := &derivation.Derivation{
		Outputs: map[string]*derivation.Output{
			"out": {
				Path: "/nix/store/abc123-foo",
			},
		},
	}
	c.add("/nix/store/xyz789-foo.drv", d)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.findDerivationForOutput(tt.outputPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDerivationCollection_FindDependencies(t *testing.T) {
	c := newDerivationCollection()

	// set up a dependency tree:
	// - foo depends on bar and baz
	// - bar depends on qux

	// Create "qux" derivation
	quxDrv := &derivation.Derivation{
		Outputs: map[string]*derivation.Output{
			"out": {
				Path: "/nix/store/qux-path",
			},
		},
	}
	c.add("/nix/store/qux.drv", quxDrv)

	// create "bar" derivation which depends on qux
	barDrv := &derivation.Derivation{
		Outputs: map[string]*derivation.Output{
			"out": {
				Path: "/nix/store/bar-path",
			},
		},
		InputDerivations: map[string][]string{
			"/nix/store/qux.drv": {"out"},
		},
	}
	c.add("/nix/store/bar.drv", barDrv)

	// create "baz" derivation
	bazDrv := &derivation.Derivation{
		Outputs: map[string]*derivation.Output{
			"out": {
				Path: "/nix/store/baz-path",
			},
		},
	}
	c.add("/nix/store/baz.drv", bazDrv)

	// create "foo" derivation which depends on bar and baz
	fooDrv := &derivation.Derivation{
		Outputs: map[string]*derivation.Output{
			"out": {
				Path: "/nix/store/foo-path",
			},
		},
		InputDerivations: map[string][]string{
			"/nix/store/bar.drv": {"out"},
			"/nix/store/baz.drv": {"out"},
		},
		InputSources: []string{
			"/nix/store/src1",
			"/nix/store/src2",
		},
	}
	c.add("/nix/store/foo.drv", fooDrv)

	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{
			name: "lookup by derivation path",
			path: "/nix/store/foo.drv",
			expected: []string{
				"/nix/store/bar-path",
				"/nix/store/baz-path",
				"/nix/store/src1",
				"/nix/store/src2",
			},
		},
		{
			name: "lookup by output path",
			path: "/nix/store/foo-path",
			expected: []string{
				"/nix/store/bar-path",
				"/nix/store/baz-path",
				"/nix/store/src1",
				"/nix/store/src2",
			},
		},
		{
			name:     "lookup by derivation with no inputs",
			path:     "/nix/store/qux.drv",
			expected: nil,
		},
		{
			name:     "lookup nonexistent path",
			path:     "/nix/store/nonexistent",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.findDependencies(tt.path)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.ElementsMatch(t, tt.expected, result)
			}
		})
	}
}

func TestDerivationCollection_NamedOutputStorePath(t *testing.T) {
	c := newDerivationCollection()

	d := &derivation.Derivation{
		Outputs: map[string]*derivation.Output{
			"out": {
				Path: "/nix/store/abc123-foo",
			},
			"dev": {
				Path: "/nix/store/def456-foo-dev",
			},
		},
	}

	c.add("/nix/store/xyz789-foo.drv", d)

	tests := []struct {
		name     string
		drvPath  string
		outName  string
		expected string
	}{
		{
			name:     "existing drv and output",
			drvPath:  "/nix/store/xyz789-foo.drv",
			outName:  "out",
			expected: "/nix/store/abc123-foo",
		},
		{
			name:     "existing drv and dev output",
			drvPath:  "/nix/store/xyz789-foo.drv",
			outName:  "dev",
			expected: "/nix/store/def456-foo-dev",
		},
		{
			name:     "existing drv but nonexistent output",
			drvPath:  "/nix/store/xyz789-foo.drv",
			outName:  "nonexistent",
			expected: "",
		},
		{
			name:     "nonexistent drv",
			drvPath:  "/nix/store/nonexistent.drv",
			outName:  "out",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.namedOutputStorePath(tt.drvPath, tt.outName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

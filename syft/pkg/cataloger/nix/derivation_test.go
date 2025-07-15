package nix

import (
	"testing"

	"github.com/nix-community/go-nix/pkg/derivation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func TestDerivationCollection_Add(t *testing.T) {
	c := newDerivations()

	d := derivationFile{
		Location: file.NewLocation("/nix/store/xyz789-foo.drv"),
		Derivation: derivation.Derivation{
			Outputs: map[string]*derivation.Output{
				"out": {
					Path: "/nix/store/abc123-foo",
				},
				"dev": {
					Path: "/nix/store/def456-foo-dev",
				},
			},
		},
	}

	c.add(d)

	assert.Len(t, c.derivationsByDrvPath, 1)
	assert.Len(t, c.drvPathByOutputPath, 2)
	assert.Equal(t, "/nix/store/xyz789-foo.drv", c.drvPathByOutputPath["/nix/store/abc123-foo"])
	assert.Equal(t, "/nix/store/xyz789-foo.drv", c.drvPathByOutputPath["/nix/store/def456-foo-dev"])
}

func TestDerivationCollection_AddNilOutputs(t *testing.T) {
	c := newDerivations()

	d := derivationFile{
		Location: file.NewLocation("/nix/store/xyz789-foo.drv"),
		Derivation: derivation.Derivation{
			Outputs: map[string]*derivation.Output{
				"out": nil,
				"dev": {
					Path: "",
				},
			},
		},
	}

	c.add(d)

	assert.Len(t, c.derivationsByDrvPath, 1)
	assert.Empty(t, c.drvPathByOutputPath)
}
func TestDerivationCollection_FindDerivationForOutputPath(t *testing.T) {
	c := newDerivations()

	// standard derivation
	standardDrv := derivationFile{
		Location: file.NewLocation("/nix/store/xyz789-foo.drv"),
		Derivation: derivation.Derivation{
			Outputs: map[string]*derivation.Output{
				"out": {
					Path: "/nix/store/abc123-foo",
				},
			},
		},
	}
	c.add(standardDrv)

	// derivation with multiple outputs
	multiOutputDrv := derivationFile{
		Location: file.NewLocation("/nix/store/multi-output.drv"),
		Derivation: derivation.Derivation{
			Outputs: map[string]*derivation.Output{
				"out": {
					Path: "/nix/store/multi-out-path",
				},
				"dev": {
					Path: "/nix/store/multi-dev-path",
				},
				"doc": {
					Path: "/nix/store/multi-doc-path",
				},
			},
		},
	}
	c.add(multiOutputDrv)

	// derivation with special characters in path
	specialCharsDrv := derivationFile{
		Location: file.NewLocation("/nix/store/special-chars+_.drv"),
		Derivation: derivation.Derivation{
			Outputs: map[string]*derivation.Output{
				"out": {
					Path: "/nix/store/special-chars+_-output",
				},
			},
		},
	}
	c.add(specialCharsDrv)

	// derivation with same output path as another (should override)
	duplicateOutputDrv := derivationFile{
		Location: file.NewLocation("/nix/store/duplicate.drv"),
		Derivation: derivation.Derivation{
			Outputs: map[string]*derivation.Output{
				"out": {
					Path: "/nix/store/abc123-foo", // same as standardDrv output
				},
			},
		},
	}
	c.add(duplicateOutputDrv)

	tests := []struct {
		name       string
		outputPath string
		expected   *derivationFile
	}{
		{
			name:       "output path exists",
			outputPath: "/nix/store/abc123-foo",
			expected:   &duplicateOutputDrv,
		},
		{
			name:       "output path exists without leading slash",
			outputPath: "nix/store/abc123-foo",
			expected:   &duplicateOutputDrv,
		},
		{
			name:       "output path does not exist",
			outputPath: "/nix/store/nonexistent",
		},
		{
			name:       "multiple output derivation - out path",
			outputPath: "/nix/store/multi-out-path",
			expected:   &multiOutputDrv,
		},
		{
			name:       "multiple output derivation - dev path",
			outputPath: "/nix/store/multi-dev-path",
			expected:   &multiOutputDrv,
		},
		{
			name:       "special characters in path",
			outputPath: "/nix/store/special-chars+_-output",
			expected:   &specialCharsDrv,
		},
		{
			name:       "empty string path",
			outputPath: "",
		},
		{
			name:       "path with just a slash",
			outputPath: "/",
		},
		{
			name:       "drv path exists in mapping but not in derivations",
			outputPath: "/nix/store/missing",
		},
	}

	// add a path mapping to a derivation that doesn't exist
	c.drvPathByOutputPath["/nix/store/missing"] = "/nix/store/nonexistent.drv"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.findDerivationForOutputPath(tt.outputPath)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.expected.Location.RealPath, result.Location.RealPath)
			}
		})
	}
}

func TestDerivationCollection_FindDependencies(t *testing.T) {
	c := newDerivations()

	// set up a dependency tree:
	// - foo depends on bar and baz
	// - bar depends on qux

	// create "qux" derivation
	quxDrv := derivationFile{
		Location: file.NewLocation("/nix/store/qux.drv"),
		Derivation: derivation.Derivation{
			Outputs: map[string]*derivation.Output{
				"out": {
					Path: "/nix/store/qux-path",
				},
			},
		},
	}
	c.add(quxDrv)

	// create "bar" derivation which depends on qux
	barDrv := derivationFile{
		Location: file.NewLocation("/nix/store/bar.drv"),
		Derivation: derivation.Derivation{
			Outputs: map[string]*derivation.Output{
				"out": {
					Path: "/nix/store/bar-path",
				},
			},
			InputDerivations: map[string][]string{
				"/nix/store/qux.drv": {"out"},
			},
		},
	}
	c.add(barDrv)

	// create "baz" derivation
	bazDrv := derivationFile{
		Location: file.NewLocation("/nix/store/baz.drv"),
		Derivation: derivation.Derivation{
			Outputs: map[string]*derivation.Output{
				"out": {
					Path: "/nix/store/baz-path",
				},
			},
		},
	}
	c.add(bazDrv)

	// create "foo" derivation which depends on bar and baz
	fooDrv := derivationFile{
		Location: file.NewLocation("/nix/store/foo.drv"),
		Derivation: derivation.Derivation{
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
		},
	}
	c.add(fooDrv)

	// add a test case for empty input names
	emptyNamesDrv := derivationFile{
		Location: file.NewLocation("/nix/store/empty-names.drv"),
		Derivation: derivation.Derivation{
			Outputs: map[string]*derivation.Output{
				"out": {
					Path: "/nix/store/empty-names-path",
				},
			},
			InputDerivations: map[string][]string{
				"/nix/store/bar.drv": {},
			},
		},
	}
	c.add(emptyNamesDrv)

	// add a test case for empty input sources
	emptySourcesDrv := derivationFile{
		Location: file.NewLocation("/nix/store/empty-sources.drv"),
		Derivation: derivation.Derivation{
			Outputs: map[string]*derivation.Output{
				"out": {
					Path: "/nix/store/empty-sources-path",
				},
			},
			InputDerivations: map[string][]string{
				"/nix/store/bar.drv": {"out"},
			},
			InputSources: []string{
				"",
			},
		},
	}
	c.add(emptySourcesDrv)

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
		{
			name:     "lookup derivation with empty input names",
			path:     "/nix/store/empty-names.drv",
			expected: nil,
		},
		{
			name: "lookup derivation with empty input sources",
			path: "/nix/store/empty-sources.drv",
			expected: []string{
				"/nix/store/bar-path",
			},
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
	c := newDerivations()

	d := derivationFile{
		Location: file.NewLocation("/nix/store/xyz789-foo.drv"),
		Derivation: derivation.Derivation{
			Outputs: map[string]*derivation.Output{
				"out": {
					Path: "/nix/store/abc123-foo",
				},
				"dev": {
					Path: "/nix/store/def456-foo-dev",
				},
			},
		},
	}

	c.add(d)

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

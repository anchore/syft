package spdxhelpers

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func Test_SourceInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected []string
	}{
		{
			name: "locations are captured",
			input: pkg.Package{
				// note: no type given
				Locations: source.NewLocationSet(
					source.NewVirtualLocation("/a-place", "/b-place"),
					source.NewVirtualLocation("/c-place", "/d-place"),
				),
			},
			expected: []string{
				"from the following paths",
				"/a-place",
				"/c-place",
			},
		},
		{
			// note: no specific support for this
			input: pkg.Package{
				Type: pkg.KbPkg,
			},
			expected: []string{
				"from the following paths",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.RpmPkg,
			},
			expected: []string{
				"from RPM DB",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.ApkPkg,
			},
			expected: []string{
				"from APK DB",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.DebPkg,
			},
			expected: []string{
				"from DPKG DB",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.NpmPkg,
			},
			expected: []string{
				"from installed node module manifest file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.PythonPkg,
			},
			expected: []string{
				"from installed python package manifest file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.JavaPkg,
			},
			expected: []string{
				"from installed java archive",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.JenkinsPluginPkg,
			},
			expected: []string{
				"from installed java archive",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.GemPkg,
			},
			expected: []string{
				"from installed gem metadata file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.GoModulePkg,
			},
			expected: []string{
				"from go module information",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.RustPkg,
			},
			expected: []string{
				"from rust cargo manifest",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.PhpComposerPkg,
			},
			expected: []string{
				"from PHP composer manifest",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.DartPubPkg,
			},
			expected: []string{
				"from pubspec manifest",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.DotnetPkg,
			},
			expected: []string{
				"from dotnet project assets file",
			},
		},
	}
	var pkgTypes []pkg.Type
	for _, test := range tests {
		t.Run(test.name+" "+string(test.input.Type), func(t *testing.T) {
			if test.input.Type != "" {
				pkgTypes = append(pkgTypes, test.input.Type)
			}
			actual := SourceInfo(test.input)
			for _, expected := range test.expected {
				assert.Contains(t, actual, expected)
			}
		})
	}
	assert.ElementsMatch(t, pkg.AllPkgs, pkgTypes, "missing one or more package types to test against (maybe a package type was added?)")
}

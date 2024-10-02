package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
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
				Locations: file.NewLocationSet(
					file.NewVirtualLocation("/a-place", "/b-place"),
					file.NewVirtualLocation("/c-place", "/d-place"),
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
				Type: pkg.PhpPeclPkg,
			},
			expected: []string{
				"from PHP Pecl manifest",
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
		{
			input: pkg.Package{
				Type: pkg.AlpmPkg,
			},
			expected: []string{
				"from ALPM DB",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.CocoapodsPkg,
			},
			expected: []string{
				"installed cocoapods manifest file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.ConanPkg,
			},
			expected: []string{
				"from conan manifest",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.PortagePkg,
			},
			expected: []string{
				"from portage DB",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.HackagePkg,
			},
			expected: []string{
				"from cabal or stack manifest files",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.BinaryPkg,
			},
			expected: []string{
				"acquired package info from the following paths",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.HexPkg,
			},
			expected: []string{
				"from rebar3 or mix manifest file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.ErlangOTPPkg,
			},
			expected: []string{
				"from ErLang application resource file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.LinuxKernelPkg,
			},
			expected: []string{
				"from linux kernel archive",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.LinuxKernelModulePkg,
			},
			expected: []string{
				"from linux kernel module files",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.NixPkg,
			},
			expected: []string{
				"from nix store path",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.Rpkg,
			},
			expected: []string{
				"acquired package info from R-package DESCRIPTION file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.LuaRocksPkg,
			},
			expected: []string{
				"acquired package info from Rockspec package file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.SwiftPkg,
			},
			expected: []string{
				"from resolved Swift package manifest",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.SwiplPackPkg,
			},
			expected: []string{
				"acquired package info from SWI Prolo pack package file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.OpamPkg,
			},
			expected: []string{
				"acquired package info from OCaml opam package file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.GithubActionPkg,
			},
			expected: []string{
				"from GitHub Actions workflow file or composite action file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.GithubActionWorkflowPkg,
			},
			expected: []string{
				"from GitHub Actions workflow file or composite action file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.WordpressPluginPkg,
			},
			expected: []string{
				"acquired package info from found wordpress plugin PHP source files",
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

package cpegenerate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func TestFromPackageAttributes_Opam(t *testing.T) {
	tests := []struct {
		name     string
		pkgName  string
		version  string
		expected []string
	}{
		{
			name:    "compiler package maps to the ocaml product",
			pkgName: "ocaml",
			version: "4.14.2",
			expected: []string{
				"cpe:2.3:a:inria:ocaml:4.14.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:ocaml:ocaml:4.14.2:*:*:*:*:*:*:*",
			},
		},
		{
			name:    "compiler implementation packages map to the ocaml product",
			pkgName: "ocaml-base-compiler",
			version: "4.14.0",
			expected: []string{
				"cpe:2.3:a:inria:ocaml:4.14.0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ocaml:ocaml:4.14.0:*:*:*:*:*:*:*",
			},
		},
		{
			name:     "opam itself",
			pkgName:  "opam-devel",
			version:  "2.1.0",
			expected: []string{"cpe:2.3:a:ocaml:opam:2.1.0:*:*:*:*:*:*:*"},
		},
		{
			name:     "library whose NVD product name differs from the opam name",
			pkgName:  "batteries",
			version:  "3.5.0",
			expected: []string{"cpe:2.3:a:ocaml_batteries_project:ocaml_batteries:3.5.0:*:*:*:*:*:*:*"},
		},
		{
			// a guessed cpe:2.3:a:fmt:fmt matches CVE-2018-1000052, which is for the C++ {fmt} library
			name:     "no guessed CPEs for packages unknown to NVD",
			pkgName:  "fmt",
			version:  "0.11.0",
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pkg.Package{
				Name:     tt.pkgName,
				Version:  tt.version,
				Type:     pkg.OpamPkg,
				Language: pkg.OCaml,
			}
			var actual []string
			for _, c := range FromPackageAttributes(p) {
				actual = append(actual, c.Attributes.String())
			}
			assert.ElementsMatch(t, tt.expected, actual)
		})
	}
}

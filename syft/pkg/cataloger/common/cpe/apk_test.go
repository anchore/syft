package cpe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_candidateVendorsForAPK(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected []string
	}{
		{
			name: "py3-cryptography Package",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Package: "py3-cryptography",
				},
			},
			expected: []string{"cryptography", "cryptographyproject", "cryptography_project"},
		},
		{
			name: "py2-pypdf OriginPackage",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					OriginPackage: "py2-pypdf",
				},
			},
			expected: []string{"pypdf", "pypdfproject", "pypdf_project"},
		},
		{
			name: "ruby-armadillo Package",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Package: "ruby-armadillo",
				},
			},
			expected: []string{"armadillo", "armadilloproject", "armadillo_project"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := candidateVendorsForAPK(test.pkg)
			assert.ElementsMatch(t, test.expected, actual, "different vendors")
		})
	}
}

func Test_candidateProductsForAPK(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected []string
	}{
		{
			name: "py3-cryptography Package",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Package: "py3-cryptography",
				},
			},
			expected: []string{"cryptography"},
		},
		{
			name: "py2-pypdf OriginPackage",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					OriginPackage: "py2-pypdf",
				},
			},
			expected: []string{"pypdf"},
		},
		{
			name: "ruby-armadillo Package",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Package: "ruby-armadillo",
				},
			},
			expected: []string{"armadillo"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := candidateProductsForAPK(test.pkg)
			assert.ElementsMatch(t, test.expected, actual, "different products")
		})
	}
}

package cpe

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
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
			expected: []string{"python-cryptography_project", "cryptography", "cryptographyproject", "cryptography_project"},
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
			expected: []string{"armadillo"},
		},
		{
			name: "python-3.6",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Package: "python-3.6",
				},
			},
			expected: []string{"python-3.6, python"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, candidateVendorsForAPK(test.pkg).values(), "different vendors")
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
			expected: []string{"cryptography", "python-cryptography"},
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
			assert.ElementsMatch(t, test.expected, candidateProductsForAPK(test.pkg).values(), "different products")
		})
	}
}

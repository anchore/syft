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
			name: "py2-pypdf with explicit different origin",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Package:       "py2-pypdf",
					OriginPackage: "abcdefg",
				},
			},
			expected: []string{"pypdf", "pypdfproject", "pypdf_project", "abcdefg"},
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
			expected: []string{"python", "python_software_foundation"},
		},
		{
			name: "ruby-3.6",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Package: "ruby-3.6",
					URL:     "https://www.ruby-lang.org/",
				},
			},
			expected: []string{"ruby", "ruby-lang"},
		},
		{
			name: "make",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Package: "make",
					URL:     "https://www.gnu.org/software/make",
				},
			},
			expected: []string{"gnu"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, candidateVendorsForAPK(test.pkg).uniqueValues(), "different vendors")
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
			name: "py2-pypdf with explicit different origin",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Package:       "py2-pypdf",
					OriginPackage: "abcdefg",
				},
			},
			expected: []string{"pypdf", "abcdefg"},
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
			expected: []string{"python"},
		},
		{
			name: "ruby-3.6",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Package: "ruby-3.6",
					URL:     "https://www.ruby-lang.org/",
				},
			},
			expected: []string{"ruby"},
		},
		{
			name: "make",
			pkg: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Package: "make",
					URL:     "https://www.gnu.org/software/make",
				},
			},
			expected: []string{"make"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, candidateProductsForAPK(test.pkg).uniqueValues(), "different products")
		})
	}
}

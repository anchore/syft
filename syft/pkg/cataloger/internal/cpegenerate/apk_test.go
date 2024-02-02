package cpegenerate

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
				Metadata: pkg.ApkDBEntry{
					Package: "py3-cryptography",
				},
			},
			expected: []string{"python-cryptography_project", "cryptography", "cryptographyproject", "cryptography_project"},
		},
		{
			name: "py2-pypdf with explicit different origin",
			pkg: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					Package:       "py2-pypdf",
					OriginPackage: "abcdefg",
				},
			},
			expected: []string{"pypdf", "pypdfproject", "pypdf_project"},
		},
		{
			name: "ruby-armadillo Package",
			pkg: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					Package: "ruby-armadillo",
				},
			},
			expected: []string{"armadillo"},
		},
		{
			name: "python-3.6",
			pkg: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					Package: "python-3.6",
				},
			},
			expected: []string{"python", "python_software_foundation"},
		},
		{
			name: "ruby-3.6",
			pkg: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					Package: "ruby-3.6",
					URL:     "https://www.ruby-lang.org/",
				},
			},
			expected: []string{"ruby", "ruby-lang"},
		},
		{
			name: "make",
			pkg: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					Package: "make",
					URL:     "https://www.gnu.org/software/make",
				},
			},
			expected: []string{"gnu", "make"},
		},
		{
			name: "ruby-rake with matching origin",
			pkg: pkg.Package{
				Name: "ruby-rake",
				Type: pkg.ApkPkg,
				Metadata: pkg.ApkDBEntry{
					Package:       "ruby-rake",
					URL:           "https://github.com/ruby/rake",
					OriginPackage: "ruby-rake",
				},
			},
			expected: []string{"rake", "ruby-lang", "ruby"},
		},
		{
			name: "ruby-rake with non-matching origin",
			pkg: pkg.Package{
				Name: "ruby-rake",
				Type: pkg.ApkPkg,
				Metadata: pkg.ApkDBEntry{
					Package:       "ruby-rake",
					URL:           "https://www.ruby-lang.org/",
					OriginPackage: "ruby",
				},
			},
			expected: []string{"rake", "ruby-lang"},
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
				Metadata: pkg.ApkDBEntry{
					Package: "py3-cryptography",
				},
			},
			expected: []string{"cryptography", "python-cryptography"},
		},
		{
			name: "py2-pypdf with explicit different origin",
			pkg: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					Package:       "py2-pypdf",
					OriginPackage: "abcdefg",
				},
			},
			expected: []string{"pypdf"},
		},
		{
			name: "ruby-armadillo Package",
			pkg: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					Package: "ruby-armadillo",
				},
			},
			expected: []string{"armadillo"},
		},
		{
			name: "python-3.6",
			pkg: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					Package: "python-3.6",
				},
			},
			expected: []string{"python"},
		},
		{
			name: "ruby-3.6",
			pkg: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					Package: "ruby-3.6",
					URL:     "https://www.ruby-lang.org/",
				},
			},
			expected: []string{"ruby"},
		},
		{
			name: "make",
			pkg: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					Package: "make",
					URL:     "https://www.gnu.org/software/make",
				},
			},
			expected: []string{"make"},
		},
		{
			name: "ruby-rake with matching origin",
			pkg: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					Package:       "ruby-rake",
					URL:           "https://github.com/ruby/rake",
					OriginPackage: "ruby-rake",
				},
			},
			expected: []string{"rake"},
		},
		{
			name: "ruby-rake with non-matching origin",
			pkg: pkg.Package{
				Name: "ruby-rake",
				Type: pkg.ApkPkg,
				Metadata: pkg.ApkDBEntry{
					Package:       "ruby-rake",
					URL:           "https://www.ruby-lang.org/",
					OriginPackage: "ruby",
				},
			},
			expected: []string{"rake"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, candidateProductsForAPK(test.pkg).uniqueValues(), "different products")
		})
	}
}

func Test_upstreamCandidates(t *testing.T) {
	tests := []struct {
		name     string
		metadata pkg.ApkDBEntry
		expected []upstreamCandidate
	}{
		{
			name: "gocase",
			metadata: pkg.ApkDBEntry{
				Package: "p",
			},
			expected: []upstreamCandidate{
				{Name: "p", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "same package and origin simple case",
			metadata: pkg.ApkDBEntry{
				Package:       "p",
				OriginPackage: "p",
			},
			expected: []upstreamCandidate{
				{Name: "p", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "different package and origin",
			metadata: pkg.ApkDBEntry{
				Package:       "p",
				OriginPackage: "origin",
			},
			expected: []upstreamCandidate{
				{Name: "p", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "upstream python package information as qualifier py- prefix",
			metadata: pkg.ApkDBEntry{
				Package:       "py-potatoes",
				OriginPackage: "py-potatoes",
			},
			expected: []upstreamCandidate{
				{Name: "potatoes", Type: pkg.PythonPkg},
			},
		},
		{
			name: "upstream python package information as qualifier py3- prefix",
			metadata: pkg.ApkDBEntry{
				Package:       "py3-potatoes",
				OriginPackage: "py3-potatoes",
			},
			expected: []upstreamCandidate{
				{Name: "potatoes", Type: pkg.PythonPkg},
			},
		},
		{
			name: "python package with distinct origin package",
			metadata: pkg.ApkDBEntry{
				Package:       "py3-non-existant",
				OriginPackage: "abcdefg",
			},
			expected: []upstreamCandidate{
				{Name: "non-existant", Type: pkg.PythonPkg},
			},
		},
		{
			name: "upstream ruby package information as qualifier",
			metadata: pkg.ApkDBEntry{
				Package:       "ruby-something",
				OriginPackage: "ruby-something",
			},
			expected: []upstreamCandidate{
				{Name: "something", Type: pkg.GemPkg},
			},
		},
		{
			name: "ruby package with distinct origin package",
			metadata: pkg.ApkDBEntry{
				Package:       "ruby-something",
				OriginPackage: "1234567",
			},
			expected: []upstreamCandidate{
				{Name: "something", Type: pkg.GemPkg},
			},
		},
		{
			name: "postgesql-15 upstream postgresql",
			metadata: pkg.ApkDBEntry{
				Package: "postgresql-15",
			},
			expected: []upstreamCandidate{
				{Name: "postgresql", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "postgesql15 upstream postgresql",
			metadata: pkg.ApkDBEntry{
				Package: "postgresql15",
			},
			expected: []upstreamCandidate{
				{Name: "postgresql", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "go-1.19 upstream go",
			metadata: pkg.ApkDBEntry{
				Package: "go-1.19",
			},
			expected: []upstreamCandidate{
				{Name: "go", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "go1.143 upstream go",
			metadata: pkg.ApkDBEntry{
				Package: "go1.143",
			},
			expected: []upstreamCandidate{
				{Name: "go", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "abc-101.191.23456 upstream abc",
			metadata: pkg.ApkDBEntry{
				Package: "abc-101.191.23456",
			},
			expected: []upstreamCandidate{
				{Name: "abc", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "abc101.191.23456 upstream abc",
			metadata: pkg.ApkDBEntry{
				Package: "abc101.191.23456",
			},
			expected: []upstreamCandidate{
				{Name: "abc", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "abc101-12345-1045 upstream abc101-12345",
			metadata: pkg.ApkDBEntry{
				Package: "abc101-12345-1045",
			},
			expected: []upstreamCandidate{
				{Name: "abc101-12345", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "abc101-a12345-1045 upstream abc101-a12345",
			metadata: pkg.ApkDBEntry{
				Package: "abc101-a12345-1045",
			},
			expected: []upstreamCandidate{
				{Name: "abc-a12345-1045", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "package starting with single digit",
			metadata: pkg.ApkDBEntry{
				Package: "3proxy",
			},
			expected: []upstreamCandidate{
				{Name: "3proxy", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "package starting with multiple digits",
			metadata: pkg.ApkDBEntry{
				Package: "356proxy",
			},
			expected: []upstreamCandidate{
				{Name: "356proxy", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "package composed of only digits",
			metadata: pkg.ApkDBEntry{
				Package: "123456",
			},
			expected: []upstreamCandidate{
				{Name: "123456", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "ruby-3.6 upstream ruby",
			metadata: pkg.ApkDBEntry{
				Package: "ruby-3.6",
			},
			expected: []upstreamCandidate{
				{Name: "ruby", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "ruby3.6 upstream ruby",
			metadata: pkg.ApkDBEntry{
				Package: "ruby3.6",
			},
			expected: []upstreamCandidate{
				{Name: "ruby", Type: pkg.UnknownPkg},
			},
		},
		{
			name: "ruby3.6-tacos upstream tacos",
			metadata: pkg.ApkDBEntry{
				Package: "ruby3.6-tacos",
			},
			expected: []upstreamCandidate{
				{Name: "tacos", Type: pkg.GemPkg},
			},
		},
		{
			name: "ruby-3.6-tacos upstream tacos",
			metadata: pkg.ApkDBEntry{
				Package: "ruby-3.6-tacos",
			},
			expected: []upstreamCandidate{
				{Name: "tacos", Type: pkg.GemPkg},
			},
		},
		{
			name: "abc1234jksajflksa",
			metadata: pkg.ApkDBEntry{
				Package: "abc1234jksajflksa",
			},
			expected: []upstreamCandidate{
				{Name: "abc1234jksajflksa", Type: pkg.UnknownPkg},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := upstreamCandidates(test.metadata)
			assert.Equal(t, test.expected, actual)
		})
	}
}

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_Homepage(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected string
	}{
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name:     "no metadata",
			input:    pkg.Package{},
			expected: "",
		},
		{
			name: "from gem",
			input: pkg.Package{
				Metadata: pkg.RubyGemspec{
					Homepage: "http://a-place.gov",
				},
			},
			expected: "http://a-place.gov",
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					Homepage: "http://a-place.gov",
				},
			},
			expected: "http://a-place.gov",
		},
		{
			name: "from rpm url",
			input: pkg.Package{
				Metadata: pkg.RpmDBEntry{URL: "https://www.gnu.org/software/bash"},
			},
			expected: "https://www.gnu.org/software/bash",
		},
		{
			name: "from apk url",
			input: pkg.Package{
				Metadata: pkg.ApkDBEntry{URL: "https://alpinelinux.org"},
			},
			expected: "https://alpinelinux.org",
		},
		{
			name: "from homebrew formula",
			input: pkg.Package{
				Metadata: pkg.HomebrewFormula{Homepage: "https://example.com"},
			},
			expected: "https://example.com",
		},
		{
			name: "from lua rocks -- falls back to url when homepage empty",
			input: pkg.Package{
				Metadata: pkg.LuaRocksPackage{URL: "https://luarocks.org/pkg"},
			},
			expected: "https://luarocks.org/pkg",
		},
		{
			name: "from r description -- first url",
			input: pkg.Package{
				Metadata: pkg.RDescription{URL: []string{"https://cran.example/pkg", "https://second"}},
			},
			expected: "https://cran.example/pkg",
		},
		{
			name: "from rpm archive url",
			input: pkg.Package{
				Metadata: pkg.RpmArchive{URL: "https://rpm-archive.example"},
			},
			expected: "https://rpm-archive.example",
		},
		{
			name: "from php composer installed entry",
			input: pkg.Package{
				Metadata: pkg.PhpComposerInstalledEntry{Homepage: "https://php.example"},
			},
			expected: "https://php.example",
		},
		{
			name: "from dart pubspec -- falls back to repository when homepage empty",
			input: pkg.Package{
				Metadata: pkg.DartPubspec{Repository: "https://github.com/acme/dartpkg"},
			},
			expected: "https://github.com/acme/dartpkg",
		},
		{
			name: "from java pom project url",
			input: pkg.Package{
				Metadata: pkg.JavaArchive{PomProject: &pkg.JavaPomProject{URL: "https://maven.example/project"}},
			},
			expected: "https://maven.example/project",
		},
		{
			name: "from dart pubspec -- all empty yields no homepage",
			input: pkg.Package{
				Metadata: pkg.DartPubspec{},
			},
			expected: "",
		},
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					Homepage: "",
				},
			},
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, Homepage(test.input))
		})
	}
}

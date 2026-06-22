package helpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_encodeExternalReferences(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected *[]cyclonedx.ExternalReference
	}{
		{
			name:     "no metadata",
			input:    pkg.Package{},
			expected: nil,
		},
		{
			name: "from apk",
			input: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					URL: "http://a-place.gov",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeDistribution},
			},
		},
		{
			name: "from npm with valid URL",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL: "http://a-place.gov",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeDistribution},
			},
		},
		{
			name: "from npm with invalid URL but valid Homepage",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL:      "b-place",
					Homepage: "http://b-place.gov",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://b-place.gov", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name: "from homebrew formula homepage",
			input: pkg.Package{
				Metadata: pkg.HomebrewFormula{
					Homepage: "https://example.com/formula",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://example.com/formula", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name: "from alpm url",
			input: pkg.Package{
				Metadata: pkg.AlpmDBEntry{
					URL: "https://archlinux.org/pkg",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://archlinux.org/pkg", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name:  "from rpm db url",
			input: pkg.Package{Metadata: pkg.RpmDBEntry{URL: "https://www.gnu.org/software/bash"}},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://www.gnu.org/software/bash", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name:  "from luarocks (homepage falls back to url)",
			input: pkg.Package{Metadata: pkg.LuaRocksPackage{URL: "https://luarocks.org/pkg"}},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://luarocks.org/pkg", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name:  "from conda url",
			input: pkg.Package{Metadata: pkg.CondaMetaPackage{URL: "https://anaconda.org/pkg"}},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://anaconda.org/pkg", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name:  "from r description (first url)",
			input: pkg.Package{Metadata: pkg.RDescription{URL: []string{"https://cran.example/pkg", "https://second"}}},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://cran.example/pkg", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name:  "from r description (repository fallback when no url)",
			input: pkg.Package{Metadata: pkg.RDescription{Repository: "https://cran.r-project.org"}},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://cran.r-project.org", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name:  "from php composer homepage",
			input: pkg.Package{Metadata: pkg.PhpComposerLockEntry{Homepage: "https://php.example"}},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://php.example", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name:  "from opam homepage",
			input: pkg.Package{Metadata: pkg.OpamPackage{Homepage: "https://opam.example"}},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://opam.example", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name:  "from dart pubspec (homepage falls back to repository)",
			input: pkg.Package{Metadata: pkg.DartPubspec{Repository: "https://github.com/acme/dartpkg"}},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://github.com/acme/dartpkg", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name:  "from swipl pack homepage",
			input: pkg.Package{Metadata: pkg.SwiplPackEntry{Homepage: "https://swipl.example"}},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://swipl.example", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name:  "from rpm archive url",
			input: pkg.Package{Metadata: pkg.RpmArchive{URL: "https://rpm-archive.example"}},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://rpm-archive.example", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name:  "from java pom project url",
			input: pkg.Package{Metadata: pkg.JavaArchive{PomProject: &pkg.JavaPomProject{URL: "https://maven.example/project"}}},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "https://maven.example/project", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name: "from cargo lock",
			input: pkg.Package{
				Name:     "ansi_term",
				Version:  "0.12.1",
				Language: pkg.Rust,
				Type:     pkg.RustPkg,
				Licenses: pkg.NewLicenseSet(),
				Metadata: pkg.RustCargoLockEntry{
					Name:     "ansi_term",
					Version:  "0.12.1",
					Source:   "registry+https://github.com/rust-lang/crates.io-index",
					Checksum: "d52a9bb7ec0cf484c551830a7ce27bd20d67eac647e1befb56b0be4ee39a55d2",
					Dependencies: []string{
						"winapi",
					},
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "registry+https://github.com/rust-lang/crates.io-index", Type: cyclonedx.ERTypeDistribution},
			},
		},
		{
			name: "from npm with homepage",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL:      "http://a-place.gov",
					Homepage: "http://homepage",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeDistribution},
				{URL: "http://homepage", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name: "from gem",
			input: pkg.Package{
				Metadata: pkg.RubyGemspec{
					Homepage: "http://a-place.gov",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name: "from python direct url",
			input: pkg.Package{
				Metadata: pkg.PythonPackage{
					DirectURLOrigin: &pkg.PythonDirectURLOriginInfo{
						URL: "http://a-place.gov",
					},
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeVCS},
			},
		},
		{
			name: "from python direct url with commit",
			input: pkg.Package{
				Metadata: pkg.PythonPackage{
					DirectURLOrigin: &pkg.PythonDirectURLOriginInfo{
						URL:      "http://a-place.gov",
						CommitID: "test",
					},
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeVCS, Comment: "commit: test"},
			},
		},
		{
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL: "",
				},
			},
			expected: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, encodeExternalReferences(test.input))
		})
	}
}

func Test_decodeExternalReferences_homepage(t *testing.T) {
	const u = "https://example.com/home"
	website := &cyclonedx.Component{
		ExternalReferences: &[]cyclonedx.ExternalReference{
			{URL: u, Type: cyclonedx.ERTypeWebsite},
		},
	}
	// each homepage-bearing metadata type must decode a website external reference back into its
	// url/homepage field
	tests := []struct {
		name string
		meta any
		got  func(any) string
	}{
		{"rpm db", &pkg.RpmDBEntry{}, func(m any) string { return m.(*pkg.RpmDBEntry).URL }},
		{"rpm archive", &pkg.RpmArchive{}, func(m any) string { return m.(*pkg.RpmArchive).URL }},
		{"alpm", &pkg.AlpmDBEntry{}, func(m any) string { return m.(*pkg.AlpmDBEntry).URL }},
		{"homebrew", &pkg.HomebrewFormula{}, func(m any) string { return m.(*pkg.HomebrewFormula).Homepage }},
		{"luarocks", &pkg.LuaRocksPackage{}, func(m any) string { return m.(*pkg.LuaRocksPackage).Homepage }},
		{"opam", &pkg.OpamPackage{}, func(m any) string { return m.(*pkg.OpamPackage).Homepage }},
		{"php composer lock", &pkg.PhpComposerLockEntry{}, func(m any) string { return m.(*pkg.PhpComposerLockEntry).Homepage }},
		{"php composer installed", &pkg.PhpComposerInstalledEntry{}, func(m any) string { return m.(*pkg.PhpComposerInstalledEntry).Homepage }},
		{"dart", &pkg.DartPubspec{}, func(m any) string { return m.(*pkg.DartPubspec).Homepage }},
		{"swipl", &pkg.SwiplPackEntry{}, func(m any) string { return m.(*pkg.SwiplPackEntry).Homepage }},
		{"conda", &pkg.CondaMetaPackage{}, func(m any) string { return m.(*pkg.CondaMetaPackage).URL }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decodeExternalReferences(website, tt.meta)
			assert.Equal(t, u, tt.got(tt.meta))
		})
	}

	// r-description decodes the website ref into the first URL slice element
	r := &pkg.RDescription{}
	decodeExternalReferences(website, r)
	assert.Equal(t, []string{u}, r.URL)

	// java archive decodes the website ref into the pom project URL, creating the pom project if absent
	j := &pkg.JavaArchive{}
	decodeExternalReferences(website, j)
	assert.NotNil(t, j.PomProject)
	assert.Equal(t, u, j.PomProject.URL)
}

func Test_isValidExternalRef(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid URL for external_reference, git protocol",
			input:    "git+https://github.com/abc/def.git",
			expected: true,
		},
		{
			name:     "valid URL for external_reference, git protocol",
			input:    "git+https://github.com/abc/def.git",
			expected: true,
		},
		{
			name:     "invalid URL for external_reference",
			input:    "abc/def",
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, isValidExternalRef(test.input))
		})
	}
}

func Test_toCycloneDXAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected cyclonedx.HashAlgorithm
	}{
		{
			name:     "valid algorithm name in upper case",
			input:    "SHA1",
			expected: cyclonedx.HashAlgorithm("SHA-1"),
		},
		{
			name:     "valid algorithm name in lower case",
			input:    "sha1",
			expected: cyclonedx.HashAlgorithm("SHA-1"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, toCycloneDXAlgorithm(test.input))
		})
	}
}

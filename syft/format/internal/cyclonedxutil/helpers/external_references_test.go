package helpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			// apk's "U:" field is the upstream project homepage, so it is emitted as a website
			// reference (not distribution, which per the CycloneDX spec is a download location)
			name: "from apk",
			input: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					URL: "http://a-place.gov",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeWebsite},
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

// Test_homepageRoundTrip drives each homepage-bearing metadata type through the real encode -> decode
// cycle and asserts the URL survives. It is the drift guard for the two lists that cannot be structurally
// unified: the encode source (internal.Homepage) and the decode setter (decodeExternalReferences). Adding
// a type to one but not the other fails here -- either encode emits no ref (require.NotNil) or decode
// drops it (assert.Equal).
func Test_homepageRoundTrip(t *testing.T) {
	const u = "https://example.com/home"
	tests := []struct {
		name  string
		meta  any // value metadata with its homepage field set, for encode
		blank any // pointer to zero metadata, for decode
		got   func(any) string
	}{
		{"rpm db", pkg.RpmDBEntry{URL: u}, &pkg.RpmDBEntry{}, func(m any) string { return m.(*pkg.RpmDBEntry).URL }},
		{"rpm archive", pkg.RpmArchive{URL: u}, &pkg.RpmArchive{}, func(m any) string { return m.(*pkg.RpmArchive).URL }},
		{"alpm", pkg.AlpmDBEntry{URL: u}, &pkg.AlpmDBEntry{}, func(m any) string { return m.(*pkg.AlpmDBEntry).URL }},
		{"apk", pkg.ApkDBEntry{URL: u}, &pkg.ApkDBEntry{}, func(m any) string { return m.(*pkg.ApkDBEntry).URL }},
		{"dpkg db", pkg.DpkgDBEntry{Homepage: u}, &pkg.DpkgDBEntry{}, func(m any) string { return m.(*pkg.DpkgDBEntry).Homepage }},
		{"dpkg archive", pkg.DpkgArchiveEntry{Homepage: u}, &pkg.DpkgArchiveEntry{}, func(m any) string { return m.(*pkg.DpkgArchiveEntry).Homepage }},
		{"python", pkg.PythonPackage{Homepage: u}, &pkg.PythonPackage{}, func(m any) string { return m.(*pkg.PythonPackage).Homepage }},
		{"homebrew", pkg.HomebrewFormula{Homepage: u}, &pkg.HomebrewFormula{}, func(m any) string { return m.(*pkg.HomebrewFormula).Homepage }},
		{"luarocks", pkg.LuaRocksPackage{Homepage: u}, &pkg.LuaRocksPackage{}, func(m any) string { return m.(*pkg.LuaRocksPackage).Homepage }},
		{"opam", pkg.OpamPackage{Homepage: u}, &pkg.OpamPackage{}, func(m any) string { return m.(*pkg.OpamPackage).Homepage }},
		{"php installed", pkg.PhpComposerInstalledEntry{Homepage: u}, &pkg.PhpComposerInstalledEntry{}, func(m any) string { return m.(*pkg.PhpComposerInstalledEntry).Homepage }},
		{"php lock", pkg.PhpComposerLockEntry{Homepage: u}, &pkg.PhpComposerLockEntry{}, func(m any) string { return m.(*pkg.PhpComposerLockEntry).Homepage }},
		{"dart", pkg.DartPubspec{Homepage: u}, &pkg.DartPubspec{}, func(m any) string { return m.(*pkg.DartPubspec).Homepage }},
		{"swipl", pkg.SwiplPackEntry{Homepage: u}, &pkg.SwiplPackEntry{}, func(m any) string { return m.(*pkg.SwiplPackEntry).Homepage }},
		{"conda", pkg.CondaMetaPackage{URL: u}, &pkg.CondaMetaPackage{}, func(m any) string { return m.(*pkg.CondaMetaPackage).URL }},
		{"r description", pkg.RDescription{URL: []string{u}}, &pkg.RDescription{}, func(m any) string { return firstOrEmpty(m.(*pkg.RDescription).URL) }},
		{"java", pkg.JavaArchive{PomProject: &pkg.JavaPomProject{URL: u}}, &pkg.JavaArchive{}, func(m any) string { return m.(*pkg.JavaArchive).PomProject.URL }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs := encodeExternalReferences(pkg.Package{Metadata: tt.meta})
			require.NotNil(t, refs, "expected a website external reference to be encoded")
			decodeExternalReferences(&cyclonedx.Component{ExternalReferences: refs}, tt.blank)
			assert.Equal(t, u, tt.got(tt.blank))
		})
	}
}

func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
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

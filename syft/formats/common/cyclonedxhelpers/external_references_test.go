package cyclonedxhelpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal"
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
				Metadata: pkg.ApkMetadata{
					URL: "http://a-place.gov",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeDistribution},
			},
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					URL: "http://a-place.gov",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeDistribution},
			},
		},
		{
			name: "from cargo lock",
			input: pkg.Package{
				Name:         "ansi_term",
				Version:      "0.12.1",
				Language:     pkg.Rust,
				Type:         pkg.RustPkg,
				MetadataType: pkg.RustCargoPackageMetadataType,
				Licenses:     internal.LogicalStrings{},
				Metadata: pkg.CargoPackageMetadata{
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
				Metadata: pkg.NpmPackageJSONMetadata{
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
				Metadata: pkg.GemMetadata{
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
				Metadata: pkg.PythonPackageMetadata{
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
				Metadata: pkg.PythonPackageMetadata{
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
				Metadata: pkg.NpmPackageJSONMetadata{
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

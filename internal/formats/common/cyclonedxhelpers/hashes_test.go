package cyclonedxhelpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_Hashes(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected *[]cyclonedx.Hash
	}{
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name:     "no metadata",
			input:    pkg.Package{},
			expected: nil,
		},
		{
			name: "from cargo lock",
			input: pkg.Package{
				Type:         pkg.RustPkg,
				MetadataType: pkg.RustCargoPackageMetadataType,
				Licenses:     nil,
				Metadata: pkg.CargoPackageMetadata{
					Checksum: "d52a9bb7ec0cf484c551830a7ce27bd20d67eac647e1befb56b0be4ee39a55d2",
				},
			},
			expected: &[]cyclonedx.Hash{
				{Algorithm: cyclonedx.HashAlgoSHA256, Value: "d52a9bb7ec0cf484c551830a7ce27bd20d67eac647e1befb56b0be4ee39a55d2"},
			},
		},
		{
			name: "from cargo lock with empty checksum",
			input: pkg.Package{
				Name:         "ansi_term",
				Version:      "0.12.1",
				Language:     pkg.Rust,
				Type:         pkg.RustPkg,
				MetadataType: pkg.RustCargoPackageMetadataType,
				Licenses:     nil,
				Metadata:     pkg.CargoPackageMetadata{},
			},
			expected: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, Hashes(test.input))
		})
	}
}

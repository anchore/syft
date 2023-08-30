package spdxtagvalue

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

// TODO: this is a temporary coverage see below
// This test should be covered within the encode decode life cycle however
// we're currently blocked on a couple of SPDX fields that change often
// which causes backward compatibility issues.
// This test was added specifically to smoke test the decode function when
// It failed on a released version of syft.
func TestSPDXTagValueDecoder(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{
			name:    "simple",
			fixture: "tag-value.spdx",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader, err := os.Open("test-fixtures/" + test.fixture)
			assert.NoError(t, err)

			_, err = Format().Decode(reader)
			assert.NoError(t, err)
		})
	}
}

func Test_packageDirectFiles(t *testing.T) {
	contents := `
SPDXVersion: SPDX-2.2
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: Some-SBOM
DocumentNamespace: https://example.org/some/namespace
Creator: Organization: Some-organization
Creator: Tool: Some-tool Version: 1.0
Created: 2021-12-29T17:02:21Z
PackageName: Some-package
PackageVersion: 5.1.2
SPDXID: SPDXRef-Package-43c51b08-cc7e-406d-8ad9-34aa292d1157
PackageSupplier: Organization: Some-organization
PackageDownloadLocation: https://example.org/download/location
FilesAnalyzed: true
PackageLicenseInfoFromFiles: NOASSERTION
PackageVerificationCode: 23460C5559C8D4DE3F6504E0E84E844CAC8B1D95
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageCopyrightText: NOASSERTION
PackageChecksum: SHA1: 23460C5559C8D4DE3F6504E0E84E844CAC8B1D95
FileName: Some-file-name
SPDXID: SPDXRef-99545d55-933d-4e08-9eb5-9d826111cb79
FileContributor: Some-file-contributor
FileType: BINARY
FileChecksum: SHA1: 23460C5559C8D4DE3F6504E0E84E844CAC8B1D95
LicenseConcluded: NOASSERTION
LicenseInfoInFile: NOASSERTION
FileCopyrightText: NOASSERTION
`

	s, err := decoder(strings.NewReader(contents))
	require.NoError(t, err)

	pkgs := s.Artifacts.Packages.Sorted()
	assert.Len(t, pkgs, 1)
	assert.Len(t, s.Artifacts.FileMetadata, 1)
	assert.Len(t, s.Relationships, 1)
	p := pkgs[0]
	r := s.Relationships[0]
	f := file.Location{}
	for c := range s.Artifacts.FileMetadata {
		f = file.Location{
			LocationData: file.LocationData{
				Coordinates: c,
				VirtualPath: "",
			},
			LocationMetadata: file.LocationMetadata{},
		}
		break // there should only be 1
	}
	assert.Equal(t, p.ID(), r.From.ID())
	assert.Equal(t, f.ID(), r.To.ID())
}

package spdxtagvalue

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

func TestDecoder_Decode(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		err      bool
		distro   string
		packages []string
	}{
		{
			name:     "dir-scan",
			file:     "snapshot/TestSPDXTagValueDirectoryEncoder.golden",
			distro:   "debian:1.2.3",
			packages: []string{"package-1:1.0.1", "package-2:2.0.1"},
		},
		{
			name:     "image-scan",
			file:     "snapshot/TestSPDXTagValueImageEncoder.golden",
			distro:   "debian:1.2.3",
			packages: []string{"package-1:1.0.1", "package-2:2.0.1"},
		},
		{
			name: "not-an-sbom",
			file: "bad-sbom",
			err:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			reader, err := os.Open(filepath.Join("test-fixtures", test.file))
			require.NoError(t, err)

			dec := NewFormatDecoder()

			formatID, formatVersion := dec.Identify(reader)
			if test.err {
				assert.Equal(t, sbom.FormatID(""), formatID)
				assert.Equal(t, "", formatVersion)
				return
			}
			assert.Equal(t, ID, formatID)
			assert.NotEmpty(t, formatVersion)

			bom, decodeID, decodeVersion, err := dec.Decode(reader)
			require.NotNil(t, bom)
			require.NoError(t, err)

			assert.Equal(t, ID, decodeID)
			assert.Equal(t, formatVersion, decodeVersion)

			var pkgs []string
			for p := range bom.Artifacts.Packages.Enumerate() {
				pkgs = append(pkgs, fmt.Sprintf("%s:%s", p.Name, p.Version))
			}

			assert.ElementsMatch(t, test.packages, pkgs)
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

	dec := NewFormatDecoder()

	s, id, version, err := dec.Decode(strings.NewReader(contents))
	require.NoError(t, err)
	assert.Equal(t, ID, id)
	assert.Equal(t, "2.2", version)

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
				AccessPath:  "",
			},
			LocationMetadata: file.LocationMetadata{},
		}
		break // there should only be 1
	}
	assert.Equal(t, p.ID(), r.From.ID())
	assert.Equal(t, f.ID(), r.To.ID())
}

func TestDecoder_Identify(t *testing.T) {
	type testCase struct {
		name    string
		file    string
		id      sbom.FormatID
		version string
	}

	var cases []testCase

	for _, version := range SupportedVersions() {
		cases = append(cases, testCase{
			name:    fmt.Sprintf("v%s schema", version),
			file:    fmt.Sprintf("test-fixtures/identify/%s.sbom", version),
			id:      ID,
			version: version,
		})
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			reader, err := os.Open(test.file)
			require.NoError(t, err)

			dec := NewFormatDecoder()

			formatID, formatVersion := dec.Identify(reader)
			assert.Equal(t, test.id, formatID)
			assert.Equal(t, test.version, formatVersion)
		})
	}
}

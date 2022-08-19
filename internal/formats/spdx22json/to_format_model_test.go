package spdx22json

import (
	"fmt"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/rekor"
	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/internal/formats/common/spdxhelpers"
	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func Test_toRelationships(t *testing.T) {

	package1 := pkg.Package{Name: "Hello World Package 1"}
	package1.SetID()
	package2 := pkg.Package{Name: "Hello World Package 2"}
	package2.SetID()
	externalRef1 := rekor.NewExternalRef("HelloWorld", "www.example.com", "SHA1", "bogushash")
	coordinates := source.Coordinates{
		RealPath: "foobar path",
	}

	tests := []struct {
		name          string
		relationships []artifact.Relationship
		result        []model.Relationship
	}{
		{
			name:   "no relationships",
			result: []model.Relationship{},
		},
		{
			name: "single external reference relationship",
			relationships: []artifact.Relationship{
				{
					From: coordinates,
					Type: artifact.DescribedByRelationship,
					To:   externalRef1,
				},
			},
			result: []model.Relationship{
				{
					SpdxElementID:      fmt.Sprint("SPDXRef-", coordinates.ID()),
					RelationshipType:   spdxhelpers.DescribedByRelationship,
					RelatedSpdxElement: fmt.Sprint("DocumentRef-", externalRef1.ID()),
				},
			},
		},
		{
			name: "single non external reference relationship",
			relationships: []artifact.Relationship{
				{
					From: package1,
					Type: artifact.ContainsRelationship,
					To:   package2,
				},
			},
			result: []model.Relationship{
				{
					SpdxElementID:      fmt.Sprint("SPDXRef-", package1.ID()),
					RelationshipType:   spdxhelpers.ContainsRelationship,
					RelatedSpdxElement: fmt.Sprint("SPDXRef-", package2.ID()),
				},
			},
		},
		{
			name: "external reference relationship does not have type DESCRIBED-BY",
			relationships: []artifact.Relationship{
				{
					From: coordinates,
					Type: artifact.ContainsRelationship,
					To:   externalRef1,
				},
			},
			result: []model.Relationship{},
		},
		{
			name: "relationship contains ExternalRef in FROM field",
			relationships: []artifact.Relationship{
				{
					From: externalRef1,
					Type: artifact.ContainsRelationship,
					To:   externalRef1,
				},
			},
			result: []model.Relationship{},
		},
		{
			name: "spdx22json cannot handle this relationship type",
			relationships: []artifact.Relationship{
				{
					From: package1,
					Type: artifact.RuntimeDependencyOfRelationship,
					To:   package2,
				},
			},
			result: []model.Relationship{},
		},
		{
			name: "both normal and external reference relationships",
			relationships: []artifact.Relationship{
				{
					From: package1,
					Type: artifact.DependencyOfRelationship,
					To:   package2,
				},
				{
					From: coordinates,
					Type: artifact.DescribedByRelationship,
					To:   externalRef1,
				},
			},
			result: []model.Relationship{
				{
					SpdxElementID:      fmt.Sprint("SPDXRef-", package1.ID()),
					RelationshipType:   spdxhelpers.DependencyOfRelationship,
					RelatedSpdxElement: fmt.Sprint("SPDXRef-", package2.ID()),
				},
				{
					SpdxElementID:      fmt.Sprint("SPDXRef-", coordinates.ID()),
					RelationshipType:   spdxhelpers.DescribedByRelationship,
					RelatedSpdxElement: fmt.Sprint("DocumentRef-", externalRef1.ID()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.result, toRelationships(test.relationships))
		})
	}
}

func Test_toExternalDocumentRefs(t *testing.T) {

	package1 := pkg.Package{Name: "Hello World Package 1"}
	package2 := pkg.Package{Name: "Hello World Package 2"}
	externalRef1 := rekor.NewExternalRef("HelloWorld", "www.example.com", "SHA1", "bogushash")
	externalRef2 := rekor.NewExternalRef("Test", "www.test.com", "sha1", "testhash")
	externalRef3 := rekor.NewExternalRef("Test", "test uri", "sha256", "sha256 test hash")

	tests := []struct {
		name          string
		relationships []artifact.Relationship
		expected      []model.ExternalDocumentRef
		exactMatch    []model.ExternalDocumentRef // check equality of list, not of elements
	}{
		{
			name:       "no relationships",
			exactMatch: []model.ExternalDocumentRef{},
		},
		{
			name: "one external relationships",
			relationships: []artifact.Relationship{
				{
					From: package1,
					To:   externalRef1,
					Type: artifact.DescribedByRelationship,
				},
			},
			expected: []model.ExternalDocumentRef{
				{
					ExternalDocumentID: model.DocElementID(externalRef1.ID()).String(),
					Checksum:           model.Checksum{Algorithm: "SHA1", ChecksumValue: "bogushash"},
					SpdxDocument:       externalRef1.SpdxRef.URI,
				},
			},
		},
		{
			name: "Both external relationships and non external relationships",
			relationships: []artifact.Relationship{
				{
					From: package1,
					To:   package2,
					Type: artifact.ContainsRelationship,
				},
				{
					From: package1,
					To:   externalRef1,
					Type: artifact.DescribedByRelationship,
				},
			},
			expected: []model.ExternalDocumentRef{
				{
					ExternalDocumentID: model.DocElementID(externalRef1.ID()).String(),
					Checksum:           model.Checksum{Algorithm: "SHA1", ChecksumValue: "bogushash"},
					SpdxDocument:       externalRef1.SpdxRef.URI,
				},
			},
		},
		{
			name: "Lowercase checksum algorithm",
			relationships: []artifact.Relationship{
				{
					From: package1,
					To:   externalRef2,
					Type: artifact.DescribedByRelationship,
				},
			},
			expected: []model.ExternalDocumentRef{
				{
					ExternalDocumentID: model.DocElementID(externalRef2.ID()).String(),
					Checksum:           model.Checksum{Algorithm: "SHA1", ChecksumValue: "testhash"},
					SpdxDocument:       externalRef2.SpdxRef.URI,
				},
			},
		},
		{
			name: "non sha1 checksum algorithm (sha1 required per spdx spec)",
			relationships: []artifact.Relationship{
				{
					From: package1,
					To:   externalRef3,
					Type: artifact.DescribedByRelationship,
				},
			},
			expected: []model.ExternalDocumentRef{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.exactMatch != nil {
				assert.Equal(t, test.exactMatch, toExternalDocumentRefs(test.relationships))
			}
			assert.ElementsMatch(t, test.expected, toExternalDocumentRefs(test.relationships))

		})
	}
}

func Test_toFiles(t *testing.T) {
	coordinates1 := source.Coordinates{RealPath: "hi there"}
	coordinates2 := source.Coordinates{RealPath: "goodbye"}

	tests := []struct {
		name          string
		inputSbom     sbom.SBOM
		expectedFiles []model.File
	}{
		{
			name: "files are created just from relationships",
			inputSbom: sbom.SBOM{
				Relationships: []artifact.Relationship{
					{
						From: coordinates1,
						To:   coordinates2,
					},
				},
			},
			expectedFiles: []model.File{
				{
					Item: model.Item{
						Element:          model.Element{SPDXID: model.ElementID(coordinates1.ID()).String()},
						LicenseConcluded: "NOASSERTION",
					},
					FileName: "hi there",
				},
				{
					Item: model.Item{
						Element:          model.Element{SPDXID: model.ElementID(coordinates2.ID()).String()},
						LicenseConcluded: "NOASSERTION",
					},
					FileName: "goodbye",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := toFiles(test.inputSbom)
			if len(res) != len(test.expectedFiles) {
				assert.FailNowf(t, "", "unexpected number of files returned, expected %v, found %v", len(test.expectedFiles), len(res))
			} else {
				for _, file := range test.expectedFiles {
					assert.Contains(t, res, file)
				}
			}
		})
	}
}

func Test_toFileTypes(t *testing.T) {

	tests := []struct {
		name     string
		metadata source.FileMetadata
		expected []string
	}{
		{
			name: "application",
			metadata: source.FileMetadata{
				MIMEType: "application/vnd.unknown",
			},
			expected: []string{
				string(spdxhelpers.ApplicationFileType),
			},
		},
		{
			name: "archive",
			metadata: source.FileMetadata{
				MIMEType: "application/zip",
			},
			expected: []string{
				string(spdxhelpers.ApplicationFileType),
				string(spdxhelpers.ArchiveFileType),
			},
		},
		{
			name: "audio",
			metadata: source.FileMetadata{
				MIMEType: "audio/ogg",
			},
			expected: []string{
				string(spdxhelpers.AudioFileType),
			},
		},
		{
			name: "video",
			metadata: source.FileMetadata{
				MIMEType: "video/3gpp",
			},
			expected: []string{
				string(spdxhelpers.VideoFileType),
			},
		},
		{
			name: "text",
			metadata: source.FileMetadata{
				MIMEType: "text/html",
			},
			expected: []string{
				string(spdxhelpers.TextFileType),
			},
		},
		{
			name: "image",
			metadata: source.FileMetadata{
				MIMEType: "image/png",
			},
			expected: []string{
				string(spdxhelpers.ImageFileType),
			},
		},
		{
			name: "binary",
			metadata: source.FileMetadata{
				MIMEType: "application/x-sharedlib",
			},
			expected: []string{
				string(spdxhelpers.ApplicationFileType),
				string(spdxhelpers.BinaryFileType),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, toFileTypes(&test.metadata))
		})
	}
}

func Test_lookupRelationship(t *testing.T) {

	tests := []struct {
		input   artifact.RelationshipType
		exists  bool
		ty      spdxhelpers.RelationshipType
		comment string
	}{
		{
			input:  artifact.ContainsRelationship,
			exists: true,
			ty:     spdxhelpers.ContainsRelationship,
		},
		{
			input:   artifact.OwnershipByFileOverlapRelationship,
			exists:  true,
			ty:      spdxhelpers.OtherRelationship,
			comment: "ownership-by-file-overlap: indicates that the parent package claims ownership of a child package since the parent metadata indicates overlap with a location that a cataloger found the child package by",
		},
		{
			input:  "made-up",
			exists: false,
		},
	}
	for _, test := range tests {
		t.Run(string(test.input), func(t *testing.T) {
			exists, ty, comment := lookupRelationship(test.input)
			assert.Equal(t, exists, test.exists)
			assert.Equal(t, ty, test.ty)
			assert.Equal(t, comment, test.comment)
		})
	}
}

func Test_toFileChecksums(t *testing.T) {
	tests := []struct {
		name     string
		digests  []file.Digest
		expected []model.Checksum
	}{
		{
			name: "empty",
		},
		{
			name: "has digests",
			digests: []file.Digest{
				{
					Algorithm: "SHA256",
					Value:     "deadbeefcafe",
				},
				{
					Algorithm: "md5",
					Value:     "meh",
				},
			},
			expected: []model.Checksum{
				{
					Algorithm:     "SHA256",
					ChecksumValue: "deadbeefcafe",
				},
				{
					Algorithm:     "MD5",
					ChecksumValue: "meh",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, toFileChecksums(test.digests))
		})
	}
}

func Test_fileIDsForPackage(t *testing.T) {

	p := pkg.Package{
		Name: "bogus",
	}

	c := source.Coordinates{
		RealPath:     "/path",
		FileSystemID: "nowhere",
	}

	tests := []struct {
		name          string
		id            string
		relationships []artifact.Relationship
		expected      []string
	}{
		{
			name: "find file IDs for packages with package-file relationships",
			id:   model.ElementID(p.ID()).String(),
			relationships: []artifact.Relationship{
				{
					From: p,
					To:   c,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []string{
				model.ElementID(c.ID()).String(),
			},
		},
		{
			name: "ignore package-to-package",
			id:   model.ElementID(p.ID()).String(),
			relationships: []artifact.Relationship{
				{
					From: p,
					To:   p,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []string{},
		},
		{
			name: "ignore file-to-file",
			id:   model.ElementID(p.ID()).String(),
			relationships: []artifact.Relationship{
				{
					From: c,
					To:   c,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []string{},
		},
		{
			name: "ignore file-to-package",
			id:   model.ElementID(p.ID()).String(),
			relationships: []artifact.Relationship{
				{
					From: c,
					To:   p,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []string{},
		},
		{
			name: "filter by relationship type",
			id:   model.ElementID(p.ID()).String(),
			relationships: []artifact.Relationship{
				{
					From: p,
					To:   c,
					Type: artifact.OwnershipByFileOverlapRelationship,
				},
			},
			expected: []string{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, fileIDsForPackage(test.id, test.relationships))
		})
	}
}

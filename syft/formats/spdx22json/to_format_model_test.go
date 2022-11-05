package spdx22json

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/formats/spdx22json/model"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

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

func Test_H1Digest(t *testing.T) {
	tests := []struct {
		name           string
		pkg            pkg.Package
		expectedDigest string
	}{
		{
			name: "valid h1digest",
			pkg: pkg.Package{
				Name:         "github.com/googleapis/gnostic",
				Version:      "v0.5.5",
				MetadataType: pkg.GolangBinMetadataType,
				Metadata: pkg.GolangBinMetadata{
					H1Digest: "h1:9fHAtK0uDfpveeqqo1hkEZJcFvYXAiCN3UutL8F9xHw=",
				},
			},
			expectedDigest: "SHA256:f5f1c0b4ad2e0dfa6f79eaaaa3586411925c16f61702208ddd4bad2fc17dc47c",
		},
		{
			name: "invalid h1digest",
			pkg: pkg.Package{
				Name:         "github.com/googleapis/gnostic",
				Version:      "v0.5.5",
				MetadataType: pkg.GolangBinMetadataType,
				Metadata: pkg.GolangBinMetadata{
					H1Digest: "h1:9fHAtK0uzzz",
				},
			},
			expectedDigest: "",
		},
		{
			name: "unsupported h-digest",
			pkg: pkg.Package{
				Name:         "github.com/googleapis/gnostic",
				Version:      "v0.5.5",
				MetadataType: pkg.GolangBinMetadataType,
				Metadata: pkg.GolangBinMetadata{
					H1Digest: "h12:9fHAtK0uDfpveeqqo1hkEZJcFvYXAiCN3UutL8F9xHw=",
				},
			},
			expectedDigest: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog := pkg.NewCatalog(test.pkg)
			pkgs := toPackages(catalog, nil)
			require.Len(t, pkgs, 1)
			p := pkgs[0]
			if test.expectedDigest == "" {
				require.Len(t, p.Checksums, 0)
			} else {
				require.Len(t, p.Checksums, 1)
				c := p.Checksums[0]
				require.Equal(t, test.expectedDigest, fmt.Sprintf("%s:%s", c.Algorithm, c.ChecksumValue))
			}
		})
	}
}

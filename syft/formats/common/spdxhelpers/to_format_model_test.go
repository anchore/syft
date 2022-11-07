package spdxhelpers

import (
	"fmt"
	"testing"

	"github.com/spdx/tools-golang/spdx/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
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
				string(ApplicationFileType),
			},
		},
		{
			name: "archive",
			metadata: source.FileMetadata{
				MIMEType: "application/zip",
			},
			expected: []string{
				string(ApplicationFileType),
				string(ArchiveFileType),
			},
		},
		{
			name: "audio",
			metadata: source.FileMetadata{
				MIMEType: "audio/ogg",
			},
			expected: []string{
				string(AudioFileType),
			},
		},
		{
			name: "video",
			metadata: source.FileMetadata{
				MIMEType: "video/3gpp",
			},
			expected: []string{
				string(VideoFileType),
			},
		},
		{
			name: "text",
			metadata: source.FileMetadata{
				MIMEType: "text/html",
			},
			expected: []string{
				string(TextFileType),
			},
		},
		{
			name: "image",
			metadata: source.FileMetadata{
				MIMEType: "image/png",
			},
			expected: []string{
				string(ImageFileType),
			},
		},
		{
			name: "binary",
			metadata: source.FileMetadata{
				MIMEType: "application/x-sharedlib",
			},
			expected: []string{
				string(ApplicationFileType),
				string(BinaryFileType),
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
		ty      RelationshipType
		comment string
	}{
		{
			input:  artifact.ContainsRelationship,
			exists: true,
			ty:     ContainsRelationship,
		},
		{
			input:   artifact.OwnershipByFileOverlapRelationship,
			exists:  true,
			ty:      OtherRelationship,
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
		expected []common.Checksum
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
			expected: []common.Checksum{
				{
					Algorithm: "SHA256",
					Value:     "deadbeefcafe",
				},
				{
					Algorithm: "MD5",
					Value:     "meh",
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

	p.SetID()

	c := source.Coordinates{
		RealPath:     "/path",
		FileSystemID: "nowhere",
	}

	tests := []struct {
		name          string
		id            common.ElementID
		relationships []artifact.Relationship
		expected      []common.ElementID
	}{
		{
			name: "find file IDs for packages with package-file relationships",
			id:   toSPDXID(p),
			relationships: []artifact.Relationship{
				{
					From: p,
					To:   c,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []common.ElementID{
				toSPDXID(c),
			},
		},
		{
			name: "ignore package-to-package",
			id:   toSPDXID(p),
			relationships: []artifact.Relationship{
				{
					From: p,
					To:   p,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []common.ElementID{},
		},
		{
			name: "ignore file-to-file",
			id:   toSPDXID(p),
			relationships: []artifact.Relationship{
				{
					From: c,
					To:   c,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []common.ElementID{},
		},
		{
			name: "ignore file-to-package",
			id:   toSPDXID(p),
			relationships: []artifact.Relationship{
				{
					From: c,
					To:   p,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []common.ElementID{},
		},
		{
			name: "filter by relationship type",
			id:   toSPDXID(p),
			relationships: []artifact.Relationship{
				{
					From: p,
					To:   c,
					Type: artifact.OwnershipByFileOverlapRelationship,
				},
			},
			expected: []common.ElementID{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var ids []common.ElementID
			for _, f := range filesForPackage(test.id, test.relationships) {
				ids = append(ids, f.FileSPDXIdentifier)
			}
			assert.ElementsMatch(t, test.expected, ids)
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
			for _, p := range pkgs {
				if test.expectedDigest == "" {
					require.Len(t, p.PackageChecksums, 0)
				} else {
					require.Len(t, p.PackageChecksums, 1)
					for _, c := range p.PackageChecksums {
						require.Equal(t, test.expectedDigest, fmt.Sprintf("%s:%s", c.Algorithm, c.Value))
					}
				}
			}
		})
	}
}

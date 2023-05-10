package spdxhelpers

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// TODO: Add ToFormatModel tests
func Test_toPackageChecksums(t *testing.T) {
	tests := []struct {
		name          string
		pkg           pkg.Package
		expected      []spdx.Checksum
		filesAnalyzed bool
	}{
		{
			name: "Java Package",
			pkg: pkg.Package{
				Name:     "test",
				Version:  "1.0.0",
				Language: pkg.Java,
				Metadata: pkg.JavaMetadata{
					ArchiveDigests: []file.Digest{
						{
							Algorithm: "sha1", // SPDX expects these to be uppercase
							Value:     "1234",
						},
					},
				},
			},
			expected: []spdx.Checksum{
				{
					Algorithm: "SHA1",
					Value:     "1234",
				},
			},
			filesAnalyzed: true,
		},
		{
			name: "Java Package with no archive digests",
			pkg: pkg.Package{
				Name:     "test",
				Version:  "1.0.0",
				Language: pkg.Java,
				Metadata: pkg.JavaMetadata{
					ArchiveDigests: []file.Digest{},
				},
			},
			expected:      []spdx.Checksum{},
			filesAnalyzed: false,
		},
		{
			name: "Java Package with no metadata",
			pkg: pkg.Package{
				Name:     "test",
				Version:  "1.0.0",
				Language: pkg.Java,
			},
			expected:      []spdx.Checksum{},
			filesAnalyzed: false,
		},
		{
			name: "Go Binary Package",
			pkg: pkg.Package{
				Name:         "test",
				Version:      "1.0.0",
				Language:     pkg.Go,
				MetadataType: pkg.GolangBinMetadataType,
				Metadata: pkg.GolangBinMetadata{
					H1Digest: "h1:9fHAtK0uDfpveeqqo1hkEZJcFvYXAiCN3UutL8F9xHw=",
				},
			},
			expected: []spdx.Checksum{
				{
					Algorithm: "SHA256",
					Value:     "f5f1c0b4ad2e0dfa6f79eaaaa3586411925c16f61702208ddd4bad2fc17dc47c",
				},
			},
			filesAnalyzed: false,
		},
		{
			name: "Package with no metadata type",
			pkg: pkg.Package{
				Name:     "test",
				Version:  "1.0.0",
				Language: pkg.Java,
				Metadata: struct{}{},
			},
			expected:      []spdx.Checksum{},
			filesAnalyzed: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			commonSum, filesAnalyzed := toPackageChecksums(test.pkg)
			assert.ElementsMatch(t, test.expected, commonSum)
			assert.Equal(t, test.filesAnalyzed, filesAnalyzed)
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
			input:   artifact.EvidentByRelationship,
			exists:  true,
			ty:      OtherRelationship,
			comment: "evident-by: indicates the package's existence is evident by the given file",
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
		expected []spdx.Checksum
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
			expected: []spdx.Checksum{
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

	c := source.Coordinates{
		RealPath:     "/path",
		FileSystemID: "nowhere",
	}

	docElementId := func(identifiable artifact.Identifiable) spdx.DocElementID {
		return spdx.DocElementID{
			ElementRefID: toSPDXID(identifiable),
		}
	}

	tests := []struct {
		name          string
		relationships []artifact.Relationship
		expected      []*spdx.Relationship
	}{
		{
			name: "package-to-file contains relationships",
			relationships: []artifact.Relationship{
				{
					From: p,
					To:   c,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []*spdx.Relationship{
				{
					Relationship: "CONTAINS",
					RefA:         docElementId(p),
					RefB:         docElementId(c),
				},
			},
		},
		{
			name: "package-to-package",
			relationships: []artifact.Relationship{
				{
					From: p,
					To:   p,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []*spdx.Relationship{
				{
					Relationship: "CONTAINS",
					RefA:         docElementId(p),
					RefB:         docElementId(p),
				},
			},
		},
		{
			name: "ignore file-to-file",
			relationships: []artifact.Relationship{
				{
					From: c,
					To:   c,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: nil,
		},
		{
			name: "ignore file-to-package",
			relationships: []artifact.Relationship{
				{
					From: c,
					To:   p,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: nil,
		},
		{
			name: "include package-to-file overlap relationships",
			relationships: []artifact.Relationship{
				{
					From: p,
					To:   c,
					Type: artifact.OwnershipByFileOverlapRelationship,
				},
			},
			expected: []*spdx.Relationship{
				{
					Relationship:        "OTHER",
					RefA:                docElementId(p),
					RefB:                docElementId(c),
					RelationshipComment: "ownership-by-file-overlap: indicates that the parent package claims ownership of a child package since the parent metadata indicates overlap with a location that a cataloger found the child package by",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			relationships := toRelationships(test.relationships)
			assert.Equal(t, test.expected, relationships)
		})
	}
}

func Test_H1Digest(t *testing.T) {
	s := sbom.SBOM{}
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
			catalog := pkg.NewCollection(test.pkg)
			pkgs := toPackages(catalog, s)
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

func Test_OtherLicenses(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected []*spdx.OtherLicense
	}{
		{
			name: "no licenseRef",
			pkg: pkg.Package{
				Licenses: pkg.NewLicenseSet(),
			},
			expected: nil,
		},
		{
			name: "single licenseRef",
			pkg: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("foobar"),
				),
			},
			expected: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-foobar",
					ExtractedText:     "foobar",
				},
			},
		},
		{
			name: "multiple licenseRef",
			pkg: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("internal made up license name"),
					pkg.NewLicense("new apple license 2.0"),
				),
			},
			expected: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-internal-made-up-license-name",
					ExtractedText:     "internal made up license name",
				},
				{
					LicenseIdentifier: "LicenseRef-new-apple-license-2.0",
					ExtractedText:     "new apple license 2.0",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog := pkg.NewCollection(test.pkg)
			otherLicenses := toOtherLicenses(catalog)
			require.Len(t, otherLicenses, len(test.expected))
			require.Equal(t, test.expected, otherLicenses)
		})
	}
}

func Test_toSPDXID(t *testing.T) {
	tests := []struct {
		name     string
		it       artifact.Identifiable
		expected string
	}{
		{
			name: "short filename",
			it: source.Coordinates{
				RealPath: "/short/path/file.txt",
			},
			expected: "File-short-path-file.txt",
		},
		{
			name: "long filename",
			it: source.Coordinates{
				RealPath: "/some/long/path/with/a/lot/of-text/that-contains-a/file.txt",
			},
			expected: "File-...a-lot-of-text-that-contains-a-file.txt",
		},
		{
			name: "package",
			it: pkg.Package{
				Type: pkg.NpmPkg,
				Name: "some-package",
			},
			expected: "Package-npm-some-package",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := string(toSPDXID(test.it))
			// trim the hash
			got = regexp.MustCompile(`-[a-z0-9]*$`).ReplaceAllString(got, "")
			require.Equal(t, test.expected, got)
		})
	}
}

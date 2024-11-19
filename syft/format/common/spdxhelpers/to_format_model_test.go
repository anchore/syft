package spdxhelpers

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal/spdxutil/helpers"
	"github.com/anchore/syft/syft/internal/sourcemetadata"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Test_toFormatModel(t *testing.T) {
	tracker := sourcemetadata.NewCompletionTester(t)

	tests := []struct {
		name     string
		in       sbom.SBOM
		expected *spdx.Document
	}{
		{
			name: "container",
			in: sbom.SBOM{
				Source: source.Description{
					Name:    "alpine",
					Version: "sha256:d34db33f",
					Metadata: source.ImageMetadata{
						UserInput:      "alpine:latest",
						ManifestDigest: "sha256:d34db33f",
					},
				},
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(pkg.Package{
						Name:    "pkg-1",
						Version: "version-1",
					}),
				},
			},
			expected: &spdx.Document{
				SPDXIdentifier: "DOCUMENT",
				SPDXVersion:    spdx.Version,
				DataLicense:    spdx.DataLicense,
				DocumentName:   "alpine",
				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier: "Package-pkg-1-pkg-1",
						PackageName:           "pkg-1",
						PackageVersion:        "version-1",
						PackageSupplier: &spdx.Supplier{
							Supplier: "NOASSERTION",
						},
					},
					{
						PackageSPDXIdentifier: "DocumentRoot-Image-alpine",
						PackageName:           "alpine",
						PackageVersion:        "sha256:d34db33f",
						PrimaryPackagePurpose: "CONTAINER",
						PackageChecksums:      []spdx.Checksum{{Algorithm: "SHA256", Value: "d34db33f"}},
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:oci/alpine@sha256:d34db33f?arch=&tag=latest",
							},
						},
						PackageSupplier: &spdx.Supplier{
							Supplier: "NOASSERTION",
						},
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA: spdx.DocElementID{
							ElementRefID: "DocumentRoot-Image-alpine",
						},
						RefB: spdx.DocElementID{
							ElementRefID: "Package-pkg-1-pkg-1",
						},
						Relationship: spdx.RelationshipContains,
					},
					{
						RefA: spdx.DocElementID{
							ElementRefID: "DOCUMENT",
						},
						RefB: spdx.DocElementID{
							ElementRefID: "DocumentRoot-Image-alpine",
						},
						Relationship: spdx.RelationshipDescribes,
					},
				},
			},
		},
		{
			name: "directory",
			in: sbom.SBOM{
				Source: source.Description{
					Name: "some/directory",
					Metadata: source.DirectoryMetadata{
						Path: "some/directory",
					},
				},
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(pkg.Package{
						Name:    "pkg-1",
						Version: "version-1",
					}),
				},
			},
			expected: &spdx.Document{
				SPDXIdentifier: "DOCUMENT",
				SPDXVersion:    spdx.Version,
				DataLicense:    spdx.DataLicense,
				DocumentName:   "some/directory",

				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier: "Package-pkg-1-pkg-1",
						PackageName:           "pkg-1",
						PackageVersion:        "version-1",
						PackageSupplier: &spdx.Supplier{
							Supplier: "NOASSERTION",
						},
					},
					{
						PackageSPDXIdentifier: "DocumentRoot-Directory-some-directory",
						PackageName:           "some/directory",
						PackageVersion:        "",
						PrimaryPackagePurpose: "FILE",
						PackageSupplier: &spdx.Supplier{
							Supplier: "NOASSERTION",
						},
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA: spdx.DocElementID{
							ElementRefID: "DocumentRoot-Directory-some-directory",
						},
						RefB: spdx.DocElementID{
							ElementRefID: "Package-pkg-1-pkg-1",
						},
						Relationship: spdx.RelationshipContains,
					},
					{
						RefA: spdx.DocElementID{
							ElementRefID: "DOCUMENT",
						},
						RefB: spdx.DocElementID{
							ElementRefID: "DocumentRoot-Directory-some-directory",
						},
						Relationship: spdx.RelationshipDescribes,
					},
				},
			},
		},
		{
			name: "file",
			in: sbom.SBOM{
				Source: source.Description{
					Name:    "path/to/some.file",
					Version: "sha256:d34db33f",
					Metadata: source.FileMetadata{
						Path: "path/to/some.file",
						Digests: []file.Digest{
							{
								Algorithm: "sha256",
								Value:     "d34db33f",
							},
						},
					},
				},
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(pkg.Package{
						Name:    "pkg-1",
						Version: "version-1",
					}),
				},
			},
			expected: &spdx.Document{
				SPDXIdentifier: "DOCUMENT",
				SPDXVersion:    spdx.Version,
				DataLicense:    spdx.DataLicense,
				DocumentName:   "path/to/some.file",
				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier: "Package-pkg-1-pkg-1",
						PackageName:           "pkg-1",
						PackageVersion:        "version-1",
						PackageSupplier: &spdx.Supplier{
							Supplier: "NOASSERTION",
						},
					},
					{
						PackageSPDXIdentifier: "DocumentRoot-File-path-to-some.file",
						PackageName:           "path/to/some.file",
						PackageVersion:        "sha256:d34db33f",
						PrimaryPackagePurpose: "FILE",
						PackageChecksums:      []spdx.Checksum{{Algorithm: "SHA256", Value: "d34db33f"}},
						PackageSupplier: &spdx.Supplier{
							Supplier: "NOASSERTION",
						},
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA: spdx.DocElementID{
							ElementRefID: "DocumentRoot-File-path-to-some.file",
						},
						RefB: spdx.DocElementID{
							ElementRefID: "Package-pkg-1-pkg-1",
						},
						Relationship: spdx.RelationshipContains,
					},
					{
						RefA: spdx.DocElementID{
							ElementRefID: "DOCUMENT",
						},
						RefB: spdx.DocElementID{
							ElementRefID: "DocumentRoot-File-path-to-some.file",
						},
						Relationship: spdx.RelationshipDescribes,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tracker.Tested(t, test.in.Source.Metadata)

			// replace IDs with package names
			var pkgs []pkg.Package
			for p := range test.in.Artifacts.Packages.Enumerate() {
				p.OverrideID(artifact.ID(p.Name))
				pkgs = append(pkgs, p)
			}
			test.in.Artifacts.Packages = pkg.NewCollection(pkgs...)

			// convert
			got := ToFormatModel(test.in)

			// check differences
			if diff := cmp.Diff(test.expected, got,
				cmpopts.IgnoreUnexported(spdx.Document{}, spdx.Package{}),
				cmpopts.IgnoreFields(spdx.Document{}, "CreationInfo", "DocumentNamespace"),
				cmpopts.IgnoreFields(spdx.Package{}, "PackageDownloadLocation", "IsFilesAnalyzedTagPresent", "PackageSourceInfo", "PackageLicenseConcluded", "PackageLicenseDeclared", "PackageCopyrightText"),
			); diff != "" {
				t.Error(diff)
			}
		})
	}
}

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
				Metadata: pkg.JavaArchive{
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
				Metadata: pkg.JavaArchive{
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
				Name:     "test",
				Version:  "1.0.0",
				Language: pkg.Go,
				Metadata: pkg.GolangBinaryBuildinfoEntry{
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
			name: "Opam Package",
			pkg: pkg.Package{
				Name:     "test",
				Version:  "1.0.0",
				Language: pkg.Go,
				Metadata: pkg.OpamPackage{
					Checksums: []string{
						"sha256=f5f1c0b4ad2e0dfa6f79eaaaa3586411925c16f61702208ddd4bad2fc17dc47c",
						"sha512=05a359dc8400d4ca200ff255dbd030acd33d2c4acb5020838f772c02cdb5f243f3dbafbc43a8cd51e6b5923a140f84c9e7ea25b2c0fa277bb68b996190d36e3b",
					},
				},
			},
			expected: []spdx.Checksum{
				{
					Algorithm: "SHA256",
					Value:     "f5f1c0b4ad2e0dfa6f79eaaaa3586411925c16f61702208ddd4bad2fc17dc47c",
				},
				{
					Algorithm: "SHA512",
					Value:     "05a359dc8400d4ca200ff255dbd030acd33d2c4acb5020838f772c02cdb5f243f3dbafbc43a8cd51e6b5923a140f84c9e7ea25b2c0fa277bb68b996190d36e3b",
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
		metadata file.Metadata
		expected []string
	}{
		{
			name: "application",
			metadata: file.Metadata{
				MIMEType: "application/vnd.unknown",
			},
			expected: []string{
				string(helpers.ApplicationFileType),
			},
		},
		{
			name: "archive",
			metadata: file.Metadata{
				MIMEType: "application/zip",
			},
			expected: []string{
				string(helpers.ApplicationFileType),
				string(helpers.ArchiveFileType),
			},
		},
		{
			name: "audio",
			metadata: file.Metadata{
				MIMEType: "audio/ogg",
			},
			expected: []string{
				string(helpers.AudioFileType),
			},
		},
		{
			name: "video",
			metadata: file.Metadata{
				MIMEType: "video/3gpp",
			},
			expected: []string{
				string(helpers.VideoFileType),
			},
		},
		{
			name: "text",
			metadata: file.Metadata{
				MIMEType: "text/html",
			},
			expected: []string{
				string(helpers.TextFileType),
			},
		},
		{
			name: "image",
			metadata: file.Metadata{
				MIMEType: "image/png",
			},
			expected: []string{
				string(helpers.ImageFileType),
			},
		},
		{
			name: "binary",
			metadata: file.Metadata{
				MIMEType: "application/x-sharedlib",
			},
			expected: []string{
				string(helpers.ApplicationFileType),
				string(helpers.BinaryFileType),
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
		ty      helpers.RelationshipType
		comment string
	}{
		{
			input:  artifact.ContainsRelationship,
			exists: true,
			ty:     helpers.ContainsRelationship,
		},
		{
			input:   artifact.OwnershipByFileOverlapRelationship,
			exists:  true,
			ty:      helpers.OtherRelationship,
			comment: "ownership-by-file-overlap: indicates that the parent package claims ownership of a child package since the parent metadata indicates overlap with a location that a cataloger found the child package by",
		},
		{
			input:   artifact.EvidentByRelationship,
			exists:  true,
			ty:      helpers.OtherRelationship,
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

	c := file.Coordinates{
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
				Name:    "github.com/googleapis/gnostic",
				Version: "v0.5.5",
				Metadata: pkg.GolangBinaryBuildinfoEntry{
					H1Digest: "h1:9fHAtK0uDfpveeqqo1hkEZJcFvYXAiCN3UutL8F9xHw=",
				},
			},
			expectedDigest: "SHA256:f5f1c0b4ad2e0dfa6f79eaaaa3586411925c16f61702208ddd4bad2fc17dc47c",
		},
		{
			name: "invalid h1digest",
			pkg: pkg.Package{
				Name:    "github.com/googleapis/gnostic",
				Version: "v0.5.5",
				Metadata: pkg.GolangBinaryBuildinfoEntry{
					H1Digest: "h1:9fHAtK0uzzz",
				},
			},
			expectedDigest: "",
		},
		{
			name: "unsupported h-digest",
			pkg: pkg.Package{
				Name:    "github.com/googleapis/gnostic",
				Version: "v0.5.5",
				Metadata: pkg.GolangBinaryBuildinfoEntry{
					H1Digest: "h12:9fHAtK0uDfpveeqqo1hkEZJcFvYXAiCN3UutL8F9xHw=",
				},
			},
			expectedDigest: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog := pkg.NewCollection(test.pkg)
			pkgs := toPackages(relationship.NewIndex(), catalog, s)
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
		{
			name: "LicenseRef as a valid spdx expression",
			pkg: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("LicenseRef-Fedora-Public-Domain"),
				),
			},
			expected: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-Fedora-Public-Domain",
					ExtractedText:     "Fedora-Public-Domain",
				},
			},
		},
		{
			name: "LicenseRef as a valid spdx expression does not otherize compound spdx expressions",
			pkg: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("(MIT AND LicenseRef-Fedora-Public-Domain)"),
				),
			},
			expected: nil,
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
			it: file.Coordinates{
				RealPath: "/short/path/file.txt",
			},
			expected: "File-short-path-file.txt",
		},
		{
			name: "long filename",
			it: file.Coordinates{
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

func Test_otherLicenses(t *testing.T) {
	pkg1 := pkg.Package{
		Name:    "first-pkg",
		Version: "1.1",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicense("MIT"),
		),
	}
	pkg2 := pkg.Package{
		Name:    "second-pkg",
		Version: "2.2",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicense("non spdx license"),
		),
	}
	bigText := `
                                 Apache License
                           Version 2.0, January 2004`
	pkg3 := pkg.Package{
		Name:    "third-pkg",
		Version: "3.3",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicense(bigText),
		),
	}

	tests := []struct {
		name     string
		packages []pkg.Package
		expected []*spdx.OtherLicense
	}{
		{
			name:     "no other licenses when all valid spdx expressions",
			packages: []pkg.Package{pkg1},
			expected: nil,
		},
		{
			name:     "other licenses includes original text",
			packages: []pkg.Package{pkg2},
			expected: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-non-spdx-license",
					ExtractedText:     "non spdx license",
				},
			},
		},
		{
			name:     "big licenses get hashed",
			packages: []pkg.Package{pkg3},
			expected: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-e9a1e42833d3e456f147052f4d312101bd171a0798893169fe596ca6b55c049e",
					ExtractedText:     bigText,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(test.packages...),
				},
			}
			got := ToFormatModel(s)
			require.Equal(t, test.expected, got.OtherLicenses)
		})
	}
}

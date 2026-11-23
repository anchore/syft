package spdxhelpers

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stfile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/internal/sourcemetadata"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal/spdxutil/helpers"
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
					Name:     "alpine",
					Version:  "sha256:d34db33f",
					Supplier: "Alpine Linux",
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
							Supplier:     "Alpine Linux",
							SupplierType: "Organization",
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
								Locator:  "pkg:oci/alpine@sha256%3Ad34db33f?arch=&tag=latest",
							},
						},
						PackageSupplier: &spdx.Supplier{
							Supplier:     "Alpine Linux",
							SupplierType: "Organization",
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
		{
			name: "snap",
			in: sbom.SBOM{
				Source: source.Description{
					Name:    "etcd",
					Version: "3.4.36",
					Metadata: source.SnapMetadata{
						Summary:     "Distributed reliable key-value store",
						Base:        "core18",
						Grade:       "stable",
						Confinement: "strict",
						Architectures: []string{
							"amd64",
						},
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
				DocumentName:   "etcd",
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
						PackageSPDXIdentifier: "DocumentRoot-Snap-etcd",
						PackageName:           "etcd",
						PackageVersion:        "3.4.36",
						PrimaryPackagePurpose: "CONTAINER",
						PackageChecksums:      []spdx.Checksum{{Algorithm: "SHA256", Value: "d34db33f"}},
						PackageSupplier: &spdx.Supplier{
							Supplier: "NOASSERTION",
						},
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA: spdx.DocElementID{
							ElementRefID: "DocumentRoot-Snap-etcd",
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
							ElementRefID: "DocumentRoot-Snap-etcd",
						},
						Relationship: spdx.RelationshipDescribes,
					},
				},
			},
		},
		{
			name: "oci-model",
			in: sbom.SBOM{
				Source: source.Description{
					Name:     "llama",
					Version:  "sha256:d34db33f",
					Supplier: "Model Provider",
					Metadata: source.OCIModelMetadata{
						UserInput:      "model-repo/llama:latest",
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
				DocumentName:   "llama",
				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier: "Package-pkg-1-pkg-1",
						PackageName:           "pkg-1",
						PackageVersion:        "version-1",
						PackageSupplier: &spdx.Supplier{
							Supplier:     "Model Provider",
							SupplierType: "Organization",
						},
					},
					{
						PackageSPDXIdentifier: "DocumentRoot-OCIModel-llama",
						PackageName:           "llama",
						PackageVersion:        "sha256:d34db33f",
						PrimaryPackagePurpose: "CONTAINER",
						PackageChecksums:      []spdx.Checksum{{Algorithm: "SHA256", Value: "d34db33f"}},
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:oci/llama@sha256%3Ad34db33f?arch=&tag=latest",
							},
						},
						PackageSupplier: &spdx.Supplier{
							Supplier:     "Model Provider",
							SupplierType: "Organization",
						},
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA: spdx.DocElementID{
							ElementRefID: "DocumentRoot-OCIModel-llama",
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
							ElementRefID: "DocumentRoot-OCIModel-llama",
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
			name: "Opam Package with a checksum missing its algorithm separator",
			pkg: pkg.Package{
				Name:    "test",
				Version: "1.0.0",
				Metadata: pkg.OpamPackage{
					Checksums: []string{"f5f1c0b4", "md5=abc"},
				},
			},
			expected: []spdx.Checksum{
				{Algorithm: "MD5", Value: "abc"},
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

func Test_toFiles(t *testing.T) {
	tests := []struct {
		name string
		in   sbom.SBOM
		want []string
	}{
		{
			name: "File paths are converted to relative in final SPDX collection",
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
					FileMetadata: map[file.Coordinates]file.Metadata{
						{
							RealPath:     "/some/path",
							FileSystemID: "",
						}: {
							Path: "/some/path",
						},
					},
				},
			},
			want: []string{"some/path"},
		},
		{
			name: "the scanned root is the root package, not a file",
			in: sbom.SBOM{Artifacts: sbom.Artifacts{FileMetadata: map[file.Coordinates]file.Metadata{
				{RealPath: ""}:     {Type: stfile.TypeDirectory},
				{RealPath: "/etc"}: {Type: stfile.TypeDirectory},
			}}},
			want: []string{"etc"},
		},
		{
			name: "a scanned directory is a file",
			in: sbom.SBOM{
				Source: source.Description{Metadata: source.DirectoryMetadata{Path: "/dir"}},
				Artifacts: sbom.Artifacts{FileMetadata: map[file.Coordinates]file.Metadata{
					{RealPath: ""}:     {Type: stfile.TypeDirectory},
					{RealPath: "/etc"}: {Type: stfile.TypeDirectory},
				}},
			},
			want: []string{".", "etc"},
		},
		{
			name: "a scanned file is indexed beside its parent directory, which was not scanned",
			in: sbom.SBOM{
				Source: source.Description{Metadata: source.FileMetadata{Path: "/dir/go.mod"}},
				Artifacts: sbom.Artifacts{FileMetadata: map[file.Coordinates]file.Metadata{
					{RealPath: ""}:        {Type: stfile.TypeDirectory},
					{RealPath: "/go.mod"}: {Type: stfile.TypeRegular},
				}},
			},
			want: []string{"go.mod"},
		},
		{
			name: "the absolute root is the root package, not a file",
			in: sbom.SBOM{Artifacts: sbom.Artifacts{FileMetadata: map[file.Coordinates]file.Metadata{
				{RealPath: "/"}:    {Type: stfile.TypeDirectory},
				{RealPath: "/etc"}: {Type: stfile.TypeDirectory},
			}}},
			want: []string{"etc"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			files, _ := toFiles(test.in, toSourceFile(test.in))
			var names []string
			for _, f := range files {
				names = append(names, f.FileName)
			}
			assert.Equal(t, test.want, names)
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

	c := file.NewCoordinates("/path", "nowhere")

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
			name: "include an archive file containing a package",
			relationships: []artifact.Relationship{
				{
					From: c,
					To:   p,
					Type: artifact.ContainsRelationship,
				},
			},
			expected: []*spdx.Relationship{
				{
					Relationship: "CONTAINS",
					RefA:         docElementId(c),
					RefB:         docElementId(p),
				},
			},
		},
		{
			name: "ignore other file-to-package",
			relationships: []artifact.Relationship{
				{
					From: c,
					To:   p,
					Type: artifact.DependencyOfRelationship,
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
			pkgs, _ := toPackages(relationship.NewIndex(), catalog, s)
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
	ctx := context.Background()
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected []spdx.OtherLicense
	}{
		{
			name: "no licenseRef",
			pkg: pkg.Package{
				Licenses: pkg.NewLicenseSet(),
			},
			expected: []spdx.OtherLicense{},
		},
		{
			name: "single licenseRef",
			pkg: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseWithContext(ctx, "foobar"),
				),
			},
			expected: []spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-foobar",
					LicenseName:       "foobar",
					ExtractedText:     "NOASSERTION",
				},
			},
		},
		{
			name: "multiple licenseRef",
			pkg: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseWithContext(ctx, "internal made up license name"),
					pkg.NewLicenseWithContext(ctx, "new apple license 2.0"),
				),
			},
			expected: []spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-internal-made-up-license-name",
					ExtractedText:     "NOASSERTION",
					LicenseName:       "internal made up license name",
				},
				{
					LicenseIdentifier: "LicenseRef-new-apple-license-2.0",
					ExtractedText:     "NOASSERTION",
					LicenseName:       "new apple license 2.0",
				},
			},
		},
		{
			name: "LicenseRef as a valid spdx expression",
			pkg: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseWithContext(ctx, "LicenseRef-Fedora-Public-Domain"),
				),
			},
			expected: []spdx.OtherLicense{},
		},
		{
			name: "LicenseRef as a valid spdx expression does not otherize compound spdx expressions",
			pkg: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseWithContext(ctx, "(MIT AND LicenseRef-Fedora-Public-Domain)"),
				),
			},
			expected: []spdx.OtherLicense{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog := pkg.NewCollection(test.pkg)
			rels := relationship.NewIndex()
			_, otherLicenses := toPackages(rels, catalog, sbom.SBOM{})
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
			name:     "short filename",
			it:       file.NewCoordinates("/short/path/file.txt", ""),
			expected: "File-short-path-file.txt",
		},
		{
			name:     "long filename",
			it:       file.NewCoordinates("/some/long/path/with/a/lot/of-text/that-contains-a/file.txt", ""),
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
		{
			name: "package with existing SPDX ID",
			it: func() pkg.Package {
				p := pkg.Package{
					Type: pkg.NpmPkg,
					Name: "some-package",
				}
				// SPDXRef- prefix is removed on decode (when everything is working as it should)
				p.OverrideID("Package-npm-some-package-extra!")
				return p
			}(),
			// note: we still sanitize out the "!" which is not allowed in SPDX IDs
			expected: "Package-npm-some-package-extra",
		},
		{
			name: "package with existing SPDX Ref",
			it: func() pkg.Package {
				p := pkg.Package{
					Type: pkg.NpmPkg,
					Name: "some-package",
				}
				// someone incorrectly added SPDXRef- prefix
				p.OverrideID("SPDXRef-Package-npm-some-package-extra!")
				return p
			}(),
			// note: we still sanitize out the "!" which is not allowed in SPDX IDs
			expected: "Package-npm-some-package-extra",
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
	ctx := context.TODO()
	pkg1 := pkg.Package{
		Name:    "first-pkg",
		Version: "1.1",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseWithContext(ctx, "MIT"),
		),
	}
	pkg2 := pkg.Package{
		Name:    "second-pkg",
		Version: "2.2",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseWithContext(ctx, "non spdx license"),
		),
	}
	bigText := `
                                 Apache License
                           Version 2.0, January 2004`
	pkg3 := pkg.Package{
		Name:    "third-pkg",
		Version: "3.3",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseWithContext(ctx, bigText),
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
			name:     "other licenses must include some original text",
			packages: []pkg.Package{pkg2},
			expected: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-non-spdx-license",
					LicenseName:       "non spdx license",
					ExtractedText:     "NOASSERTION",
				},
			},
		},
		{
			name:     "big licenses get hashed and space is trimmed",
			packages: []pkg.Package{pkg3},
			expected: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-3f17782eef51ae86f18fdd6832f5918e2b40f688b52c9adc07ba6ec1024ef408",
					// Carries through the syft-json license value when we shasum large texts
					LicenseName:   "sha256:3f17782eef51ae86f18fdd6832f5918e2b40f688b52c9adc07ba6ec1024ef408",
					ExtractedText: strings.TrimSpace(bigText),
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

func Test_nestedArchiveFiles(t *testing.T) {
	top := file.NewCoordinates("/etc/os-release", "sha256:layer")
	inA := file.Coordinates{RealPath: "/app.war", FullPath: "/app.war!/WEB-INF/lib/a.jar!/META-INF/MANIFEST.MF", FileSystemID: "sha256:layer"}
	inB := file.Coordinates{RealPath: "/app.war", FullPath: "/app.war!/WEB-INF/lib/b.jar!/odd:na%me.txt", FileSystemID: "sha256:layer"}
	owned := file.NewCoordinates("/usr/bin/tool", "sha256:layer")
	a := file.Coordinates{RealPath: "/app.war", FullPath: "/app.war!/WEB-INF/lib/a.jar", FileSystemID: "sha256:layer"}
	war := file.NewCoordinates("/app.war", "sha256:layer")
	b := file.Coordinates{RealPath: "/app.war", FullPath: "/app.war!/WEB-INF/lib/b.jar", FileSystemID: "sha256:layer"}
	topPkg := pkg.Package{Name: "top"}
	topPkg.SetID()
	nestedPkg := pkg.Package{Name: "nested"}
	nestedPkg.SetID()

	sources := []source.Description{
		{Name: "img", Metadata: source.ImageMetadata{UserInput: "img:latest", ManifestDigest: "sha256:abc"}},
		{Name: "dir", Metadata: source.DirectoryMetadata{Path: "/dir"}},
	}
	for _, src := range sources {
		t.Run(src.Name, func(t *testing.T) {
			s := sbom.SBOM{
				Source: src,
				Artifacts: sbom.Artifacts{
					Packages:     pkg.NewCollection(topPkg, nestedPkg),
					FileMetadata: map[file.Coordinates]file.Metadata{top: {}, inA: {}, inB: {}, owned: {}},
				},
				Relationships: []artifact.Relationship{
					{From: topPkg, To: owned, Type: artifact.ContainsRelationship},
					{From: a, To: nestedPkg, Type: artifact.ContainsRelationship},
				},
			}

			doc := ToFormatModel(s)

			// each archive holding a described file is described too, named by its path in its own container
			names := map[spdx.ElementID]string{}
			for _, f := range doc.Files {
				names[f.FileSPDXIdentifier] = f.FileName
				assert.Equal(t, "layerID: sha256:layer", f.FileComment)
			}
			assert.Equal(t, map[spdx.ElementID]string{
				toSPDXID(top):   "etc/os-release",
				toSPDXID(owned): "usr/bin/tool",
				toSPDXID(war):   "app.war",
				toSPDXID(a):     "WEB-INF/lib/a.jar",
				toSPDXID(b):     "WEB-INF/lib/b.jar",
				toSPDXID(inA):   "META-INF/MANIFEST.MF",
				toSPDXID(inB):   "odd:na%me.txt",
			}, names)

			var described []spdx.ElementID
			var contains [][2]spdx.ElementID
			for _, r := range doc.Relationships {
				switch r.Relationship {
				case string(helpers.DescribesRelationship):
					described = append(described, r.RefB.ElementRefID)
				case string(helpers.ContainsRelationship):
					contains = append(contains, [2]spdx.ElementID{r.RefA.ElementRefID, r.RefB.ElementRefID})
				}
			}
			rootPkg := doc.Packages[len(doc.Packages)-1]
			root := rootPkg.PackageSPDXIdentifier
			assert.Equal(t, []spdx.ElementID{root}, described)

			// the root contains every package, but only the files nothing else does: not what is within an archive,
			// nor an owned file
			assert.ElementsMatch(t, [][2]spdx.ElementID{
				{root, toSPDXID(topPkg)},
				{root, toSPDXID(nestedPkg)},
				{root, toSPDXID(top)},
				{root, toSPDXID(war)},
				{toSPDXID(topPkg), toSPDXID(owned)},
				{toSPDXID(a), toSPDXID(nestedPkg)},
				{toSPDXID(war), toSPDXID(a)},
				{toSPDXID(war), toSPDXID(b)},
				{toSPDXID(a), toSPDXID(inA)},
				{toSPDXID(b), toSPDXID(inB)},
			}, contains)

			// a package containing files must have analyzed them
			assert.True(t, rootPkg.FilesAnalyzed)
			assert.NotNil(t, rootPkg.PackageVerificationCode)

			// other tools may instead have the document describe the top-level files directly
			describesFiles := ToFormatModel(s)
			for _, r := range describesFiles.Relationships {
				if r.RefA.ElementRefID == root && (r.RefB.ElementRefID == toSPDXID(top) || r.RefB.ElementRefID == toSPDXID(war)) {
					r.RefA.ElementRefID = "DOCUMENT"
					r.Relationship = string(helpers.DescribesRelationship)
				}
			}

			for _, d := range []struct {
				name string
				doc  *spdx.Document
			}{
				{name: "root contains files", doc: doc},
				{name: "document describes files", doc: describesFiles},
			} {
				t.Run(d.name, func(t *testing.T) {
					decoded, err := ToSyftModel(d.doc)
					require.NoError(t, err)

					assert.Equal(t, src.Name, decoded.Source.Name)
					assert.IsType(t, src.Metadata, decoded.Source.Metadata)

					// decoded paths are relative, as SPDX names are
					relative := func(c file.Coordinates) file.Coordinates {
						c.RealPath = strings.TrimPrefix(c.RealPath, "/")
						c.FullPath = strings.TrimPrefix(c.FullPath, "/")
						return c
					}
					var got []file.Coordinates
					for c := range decoded.Artifacts.FileMetadata {
						got = append(got, c)
					}
					assert.ElementsMatch(t, []file.Coordinates{relative(top), relative(owned), relative(war), relative(a), relative(b), relative(inA), relative(inB)}, got)

					var gotContains []artifact.Relationship
					for _, r := range decoded.Relationships {
						_, fromFile := r.From.(file.Coordinates)
						_, toFile := r.To.(file.Coordinates)
						if fromFile && toFile {
							gotContains = append(gotContains, r)
						}
					}
					assert.ElementsMatch(t, []artifact.Relationship{
						{From: relative(war), To: relative(a), Type: artifact.ContainsRelationship},
						{From: relative(war), To: relative(b), Type: artifact.ContainsRelationship},
						{From: relative(a), To: relative(inA), Type: artifact.ContainsRelationship},
						{From: relative(b), To: relative(inB), Type: artifact.ContainsRelationship},
					}, gotContains)
				})
			}
		})
	}
}

func Test_sourceFile(t *testing.T) {
	root := file.NewCoordinates("", "")
	war := file.NewCoordinates("/app.war", "")
	jar := file.Coordinates{RealPath: "/app.war", FullPath: "/app.war!/a.jar"}
	etc := file.NewCoordinates("/etc/os-release", "")
	p := pkg.Package{Name: "p"}
	p.SetID()

	tests := []struct {
		name   string
		source source.Description
		files  []file.Coordinates
		// relationships as "from type to", with the root package as "root"
		want         []string
		wantAnalyzed bool
		// the file types of the file the root package describes
		wantTypes []string
		// decoded files, and the file relationships among them, as "from type to"
		wantFiles    []string
		wantContains []string
	}{
		{
			name:   "a scanned directory is described, and contains what is at its root",
			source: source.Description{Name: "dir", Metadata: source.DirectoryMetadata{Path: "/dir"}},
			files:  []file.Coordinates{root, etc, war, jar},
			want: []string{
				"root DESCRIBES .",
				"root CONTAINS p",
				". CONTAINS etc/os-release",
				". CONTAINS app.war",
				"app.war CONTAINS a.jar",
			},
			// the scanned root decodes back to the scanned root, and holds nothing as an archive would
			wantFiles:    []string{"", "etc/os-release", "app.war", "app.war!/a.jar"},
			wantContains: []string{"app.war contains app.war!/a.jar"},
		},
		{
			name:   "an extracted archive is described, and contains what is at its root",
			source: source.Description{Name: "t.tar", Metadata: source.FileMetadata{Path: "/dir/t.tar"}},
			files:  []file.Coordinates{root, etc},
			want: []string{
				"root DESCRIBES t.tar",
				"root CONTAINS p",
				"t.tar CONTAINS etc/os-release",
			},
			// the scanned root is the directory the archive was extracted to, but describes the archive
			wantTypes: []string{"ARCHIVE"},
			// the described archive is the scanned root, holding what is at the root
			wantFiles: []string{"", "etc/os-release"},
		},
		{
			name:   "an extracted archive takes its file types from its MIME type",
			source: source.Description{Name: "t.zip", Metadata: source.FileMetadata{Path: "/dir/t.zip", MIMEType: "application/zip"}},
			files:  []file.Coordinates{root, etc},
			want: []string{
				"root DESCRIBES t.zip",
				"root CONTAINS p",
				"t.zip CONTAINS etc/os-release",
			},
			wantTypes: []string{"APPLICATION", "ARCHIVE"},
			wantFiles: []string{"", "etc/os-release"},
		},
		{
			name:   "a scanned file is described, but not its parent directory",
			source: source.Description{Name: "app.war", Metadata: source.FileMetadata{Path: "/dir/app.war"}},
			files:  []file.Coordinates{root, war, jar},
			want: []string{
				"root DESCRIBES app.war",
				"root CONTAINS p",
				"app.war CONTAINS a.jar",
			},
			// an archive read in place is the scanned root too, so decodes as if it had been extracted
			wantFiles: []string{"", "a.jar"},
		},
		{
			name:   "without the scanned root, the root package contains what is at its root",
			source: source.Description{Name: "dir", Metadata: source.DirectoryMetadata{Path: "/dir"}},
			files:  []file.Coordinates{etc},
			want: []string{
				"root CONTAINS p",
				"root CONTAINS etc/os-release",
			},
			wantAnalyzed: true,
			wantFiles:    []string{"etc/os-release"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := map[file.Coordinates]file.Metadata{}
			for _, c := range tt.files {
				metadata[c] = file.Metadata{}
			}
			s := sbom.SBOM{
				Source:    tt.source,
				Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(p), FileMetadata: metadata},
			}

			doc := ToFormatModel(s)

			rootPkg := doc.Packages[len(doc.Packages)-1]
			names := map[spdx.ElementID]string{rootPkg.PackageSPDXIdentifier: "root", toSPDXID(p): "p"}
			for _, f := range doc.Files {
				names[f.FileSPDXIdentifier] = f.FileName
			}
			var got []string
			for _, r := range doc.Relationships {
				if r.RefA.ElementRefID == "DOCUMENT" {
					continue
				}
				got = append(got, names[r.RefA.ElementRefID]+" "+r.Relationship+" "+names[r.RefB.ElementRefID])
			}
			assert.ElementsMatch(t, tt.want, got)
			assert.Equal(t, tt.wantAnalyzed, rootPkg.FilesAnalyzed)
			if tt.wantTypes != nil {
				for _, r := range doc.Relationships {
					if r.RefA.ElementRefID == rootPkg.PackageSPDXIdentifier && r.Relationship == string(helpers.DescribesRelationship) {
						i := slices.IndexFunc(doc.Files, func(f *spdx.File) bool { return f.FileSPDXIdentifier == r.RefB.ElementRefID })
						require.GreaterOrEqual(t, i, 0)
						assert.Equal(t, tt.wantTypes, doc.Files[i].FileTypes)
					}
				}
			}

			decoded, err := ToSyftModel(doc)
			require.NoError(t, err)

			var gotFiles []string
			for c := range decoded.Artifacts.FileMetadata {
				gotFiles = append(gotFiles, c.FullNestedPath())
			}
			assert.ElementsMatch(t, tt.wantFiles, gotFiles)

			var gotContains []string
			for _, r := range decoded.Relationships {
				if from, ok := r.From.(file.Coordinates); ok {
					to, _ := r.To.(file.Coordinates)
					gotContains = append(gotContains, from.FullNestedPath()+" "+string(r.Type)+" "+to.FullNestedPath())
				}
			}
			assert.ElementsMatch(t, tt.wantContains, gotContains)
		})
	}
}

func Test_toRootPackage_name(t *testing.T) {
	tests := []struct {
		name     string
		src      source.Description
		wantName string
		wantPurl string
	}{
		{
			name:     "source name wins",
			src:      source.Description{Name: "named", ID: "id", Metadata: source.ImageMetadata{UserInput: "alpine:3.18"}},
			wantName: "named",
		},
		{
			// a CycloneDX container component decodes to an image source with only the user input set
			name: "image user input without a source name",
			src: source.Description{Metadata: source.ImageMetadata{
				UserInput:      "alpine:3.18",
				ManifestDigest: "sha256:0e4b2e0d6b2f3c2b1d3bb3a1c8f1c4d9e6a9b1e8c6f4d2b3a1f0e9d8c7b6a5f4",
			}},
			wantName: "alpine",
			wantPurl: "pkg:oci/alpine@sha256%3A0e4b2e0d6b2f3c2b1d3bb3a1c8f1c4d9e6a9b1e8c6f4d2b3a1f0e9d8c7b6a5f4?arch=&tag=3.18",
		},
		{
			name:     "id without a source name",
			src:      source.Description{ID: "some-id"},
			wantName: "some-id",
		},
		{
			name:     "nothing to name it by",
			src:      source.Description{Metadata: source.DirectoryMetadata{}},
			wantName: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := toRootPackage(tt.src)
			assert.Equal(t, tt.wantName, p.PackageName)
			var purl string
			if len(p.PackageExternalReferences) > 0 {
				purl = p.PackageExternalReferences[0].Locator
			}
			assert.Equal(t, tt.wantPurl, purl)
		})
	}
}

func Test_toFiles_archiveType(t *testing.T) {
	// a file holding entries is an archive, even when its content starts like something else, such as a Spring Boot
	// executable jar's launch script
	jar := file.NewCoordinates("/app.jar", "")
	s := sbom.SBOM{Artifacts: sbom.Artifacts{FileMetadata: map[file.Coordinates]file.Metadata{
		jar:                                   {MIMEType: "text/x-shellscript"},
		file.NewCoordinates("/plain.zip", ""): {MIMEType: "application/zip"},
		{RealPath: "/app.jar", FullPath: "/app.jar!/lib/b.jar!/c.txt"}: {MIMEType: "text/plain"},
	}}}

	files, _ := toFiles(s, nil)
	got := map[string][]string{}
	for _, f := range files {
		got[f.FileName] = f.FileTypes
	}
	assert.Equal(t, map[string][]string{
		"app.jar":   {"TEXT", "ARCHIVE"},
		"plain.zip": {"APPLICATION", "ARCHIVE"},
		// added only to hold its entry, with no metadata of its own
		"lib/b.jar": {"ARCHIVE"},
		"c.txt":     {"TEXT"},
	}, got)
}

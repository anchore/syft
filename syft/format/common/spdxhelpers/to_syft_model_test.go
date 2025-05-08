package spdxhelpers

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func TestToSyftModel(t *testing.T) {
	sbom, err := ToSyftModel(&spdx.Document{
		SPDXVersion:                "1",
		DataLicense:                "GPL",
		SPDXIdentifier:             "id-doc-1",
		DocumentName:               "docName",
		DocumentNamespace:          "docNamespace",
		ExternalDocumentReferences: nil,
		DocumentComment:            "",
		CreationInfo: &spdx.CreationInfo{
			LicenseListVersion: "",
			Created:            "",
			CreatorComment:     "",
		},
		Packages: []*spdx.Package{
			{
				PackageName:            "pkg-1",
				PackageSPDXIdentifier:  "id-pkg-1",
				PackageVersion:         "5.4.3",
				PackageLicenseDeclared: "",
				PackageDescription:     "",
				PackageExternalReferences: []*spdx.PackageExternalReference{
					{
						Category: "SECURITY",
						Locator:  "cpe:2.3:a:pkg-1:pkg-1:5.4.3:*:*:*:*:*:*:*",
						RefType:  "cpe23Type",
					},
					{
						Category: "SECURITY",
						Locator:  "cpe:2.3:a:pkg_1:pkg_1:5.4.3:*:*:*:*:*:*:*",
						RefType:  "cpe23Type",
					},
					{
						Category: "PACKAGE-MANAGER",
						Locator:  "pkg:apk/alpine/pkg-1@5.4.3?arch=x86_64&upstream=p1-origin&distro=alpine-3.10.9",
						RefType:  "purl",
					},
				},
				Files: nil,
			},
			{
				PackageName:            "pkg-2",
				PackageSPDXIdentifier:  "id-pkg-2",
				PackageVersion:         "7.3.1",
				PackageLicenseDeclared: "",
				PackageDescription:     "",
				PackageExternalReferences: []*spdx.PackageExternalReference{
					{
						Category: "SECURITY",
						Locator:  "cpe:2.3:a:pkg-2:pkg-2:7.3.1:*:*:*:*:*:*:*",
						RefType:  "cpe23Type",
					},
					{
						Category: "SECURITY",
						Locator:  "cpe:2.3:a:pkg_2:pkg_2:7.3.1:*:*:*:*:*:*:*",
						RefType:  "cpe23Type",
					},
					{
						Category: "SECURITY",
						Locator:  "cpe:2.3:a:pkg-2:pkg_2:7.3.1:*:*:*:*:*:*:*",
						RefType:  "cpe23Type",
					},
					{
						Category: "PACKAGE-MANAGER",
						Locator:  "pkg:deb/pkg-2@7.3.1?arch=x86_64&upstream=p2-origin@9.1.3&distro=debian-3.10.9",
						RefType:  "purl",
					},
				},
				Files: nil,
			},
		},
		Relationships: []*spdx.Relationship{},
	})

	assert.NoError(t, err)

	assert.NotNil(t, sbom)

	pkgs := sbom.Artifacts.Packages.Sorted()

	assert.Len(t, pkgs, 2)

	p1 := pkgs[0]
	assert.Equal(t, p1.Name, "pkg-1")
	p1meta := p1.Metadata.(pkg.ApkDBEntry)
	assert.Equal(t, p1meta.OriginPackage, "p1-origin")
	assert.Len(t, p1.CPEs, 2)

	p2 := pkgs[1]
	assert.Equal(t, p2.Name, "pkg-2")
	p2meta := p2.Metadata.(pkg.DpkgDBEntry)
	assert.Equal(t, p2meta.Source, "p2-origin")
	assert.Equal(t, p2meta.SourceVersion, "9.1.3")
	assert.Len(t, p2.CPEs, 3)
}

func Test_extractMetadata(t *testing.T) {
	oneTwoThreeFour := 1234
	tests := []struct {
		pkg  spdx.Package
		meta interface{}
	}{
		{
			pkg: spdx.Package{
				PackageName:    "SomeDebPkg",
				PackageVersion: "43.1.235",
				PackageExternalReferences: []*spdx.PackageExternalReference{
					{
						Category: "PACKAGE-MANAGER",
						Locator:  "pkg:deb/pkg-2@7.3.1?arch=x86_64&upstream=somedebpkg-origin@9.1.3&distro=debian-3.10.9",
						RefType:  "purl",
					},
				},
			},
			meta: pkg.DpkgDBEntry{
				Package:       "SomeDebPkg",
				Source:        "somedebpkg-origin",
				Version:       "43.1.235",
				SourceVersion: "9.1.3",
				Architecture:  "x86_64",
			},
		},
		{
			pkg: spdx.Package{
				PackageName:    "SomeApkPkg",
				PackageVersion: "3.2.9",
				PackageExternalReferences: []*spdx.PackageExternalReference{
					{
						Category: "PACKAGE-MANAGER",
						Locator:  "pkg:apk/alpine/pkg-2@7.3.1?arch=x86_64&upstream=apk-origin@9.1.3&distro=alpine-3.10.9",
						RefType:  "purl",
					},
				},
			},
			meta: pkg.ApkDBEntry{
				Package:       "SomeApkPkg",
				OriginPackage: "apk-origin",
				Version:       "3.2.9",
				Architecture:  "x86_64",
			},
		},
		{
			pkg: spdx.Package{
				PackageName:    "SomeRpmPkg",
				PackageVersion: "13.2.79",
				PackageExternalReferences: []*spdx.PackageExternalReference{
					{
						Category: "PACKAGE-MANAGER",
						Locator:  "pkg:rpm/pkg-2@7.3.1?arch=x86_64&epoch=1234&upstream=some-rpm-origin-1.16.3&distro=alpine-3.10.9",
						RefType:  "purl",
					},
				},
			},
			meta: pkg.RpmDBEntry{
				Name:      "SomeRpmPkg",
				Version:   "13.2.79",
				Epoch:     &oneTwoThreeFour,
				Arch:      "x86_64",
				Release:   "",
				SourceRpm: "some-rpm-origin-1.16.3",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.pkg.PackageName, func(t *testing.T) {
			info := extractPkgInfo(&test.pkg)
			meta := extractMetadata(&test.pkg, info)
			assert.EqualValues(t, test.meta, meta)
		})
	}
}

func TestExtractSourceFromNamespaces(t *testing.T) {
	tests := []struct {
		namespace string
		expected  any
	}{
		{
			namespace: "https://anchore.com/syft/file/d42b01d0-7325-409b-b03f-74082935c4d3",
			expected:  source.FileMetadata{},
		},
		{
			namespace: "https://anchore.com/syft/image/d42b01d0-7325-409b-b03f-74082935c4d3",
			expected:  source.ImageMetadata{},
		},
		{
			namespace: "https://anchore.com/syft/dir/d42b01d0-7325-409b-b03f-74082935c4d3",
			expected:  source.DirectoryMetadata{},
		},
		{
			namespace: "https://another-host/blob/123",
			expected:  nil,
		},
		{
			namespace: "bla bla",
			expected:  nil,
		},
		{
			namespace: "",
			expected:  nil,
		},
	}

	for _, tt := range tests {
		desc := extractSourceFromNamespace(tt.namespace)
		if tt.expected == nil && desc.Metadata == nil {
			return
		}
		if tt.expected != nil && desc.Metadata == nil {
			t.Fatal("expected metadata but got nil")
		}
		if tt.expected == nil && desc.Metadata != nil {
			t.Fatal("expected nil metadata but got something")
		}
		require.Equal(t, reflect.TypeOf(tt.expected), reflect.TypeOf(desc.Metadata))
	}
}

func TestH1Digest(t *testing.T) {
	tests := []struct {
		name           string
		pkg            spdx.Package
		expectedDigest string
	}{
		{
			name: "valid h1digest",
			pkg: spdx.Package{
				PackageName:    "github.com/googleapis/gnostic",
				PackageVersion: "v0.5.5",
				PackageExternalReferences: []*spdx.PackageExternalReference{
					{
						Category: "PACKAGE-MANAGER",
						Locator:  "pkg:golang/github.com/googleapis/gnostic@v0.5.5",
						RefType:  "purl",
					},
				},
				PackageChecksums: []spdx.Checksum{
					{
						Algorithm: spdx.SHA256,
						Value:     "f5f1c0b4ad2e0dfa6f79eaaaa3586411925c16f61702208ddd4bad2fc17dc47c",
					},
				},
			},
			expectedDigest: "h1:9fHAtK0uDfpveeqqo1hkEZJcFvYXAiCN3UutL8F9xHw=",
		},
		{
			name: "invalid h1digest algorithm",
			pkg: spdx.Package{
				PackageName:    "github.com/googleapis/gnostic",
				PackageVersion: "v0.5.5",
				PackageExternalReferences: []*spdx.PackageExternalReference{
					{
						Category: "PACKAGE-MANAGER",
						Locator:  "pkg:golang/github.com/googleapis/gnostic@v0.5.5",
						RefType:  "purl",
					},
				},
				PackageChecksums: []spdx.Checksum{
					{
						Algorithm: spdx.SHA1,
						Value:     "f5f1c0b4ad2e0dfa6f79eaaaa3586411925c16f61702208ddd4bad2fc17dc47c",
					},
				},
			},
			expectedDigest: "",
		},
		{
			name: "invalid h1digest digest",
			pkg: spdx.Package{
				PackageName:    "github.com/googleapis/gnostic",
				PackageVersion: "v0.5.5",
				PackageExternalReferences: []*spdx.PackageExternalReference{
					{
						Category: "PACKAGE-MANAGER",
						Locator:  "pkg:golang/github.com/googleapis/gnostic@v0.5.5",
						RefType:  "purl",
					},
				},
				PackageChecksums: []spdx.Checksum{
					{
						Algorithm: spdx.SHA256,
						Value:     "",
					},
				},
			},
			expectedDigest: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := toSyftPackage(&test.pkg)
			meta := p.Metadata.(pkg.GolangBinaryBuildinfoEntry)
			require.Equal(t, test.expectedDigest, meta.H1Digest)
		})
	}
}

func Test_toSyftRelationships(t *testing.T) {
	type args struct {
		spdxIDMap map[string]any
		doc       *spdx.Document
	}

	pkg1 := pkg.Package{
		Name:    "github.com/googleapis/gnostic",
		Version: "v0.5.5",
	}
	pkg1.SetID()

	pkg2 := pkg.Package{
		Name:    "rfc3339",
		Version: "1.2",
		Type:    pkg.RpmPkg,
	}
	pkg2.SetID()

	pkg3 := pkg.Package{
		Name:    "rfc3339",
		Version: "1.2",
		Type:    pkg.PythonPkg,
	}
	pkg3.SetID()

	loc1 := file.NewLocationFromCoordinates(file.Coordinates{
		RealPath:     "/somewhere/real",
		FileSystemID: "abc",
	})

	tests := []struct {
		name string
		args args
		want []artifact.Relationship
	}{
		{
			name: "evident-by relationship",
			args: args{
				spdxIDMap: map[string]any{
					string(toSPDXID(pkg1)): pkg1,
					string(toSPDXID(loc1)): loc1,
				},
				doc: &spdx.Document{
					Relationships: []*spdx.Relationship{
						{
							RefA: common.DocElementID{
								ElementRefID: toSPDXID(pkg1),
							},
							RefB: common.DocElementID{
								ElementRefID: toSPDXID(loc1),
							},
							Relationship:        spdx.RelationshipOther,
							RelationshipComment: "evident-by: indicates the package's existence is evident by the given file",
						},
					},
				},
			},
			want: []artifact.Relationship{
				{
					From: pkg1,
					To:   loc1,
					Type: artifact.EvidentByRelationship,
				},
			},
		},
		{
			name: "ownership-by-file-overlap relationship",
			args: args{
				spdxIDMap: map[string]any{
					string(toSPDXID(pkg2)): pkg2,
					string(toSPDXID(pkg3)): pkg3,
				},
				doc: &spdx.Document{
					Relationships: []*spdx.Relationship{
						{
							RefA: common.DocElementID{
								ElementRefID: toSPDXID(pkg2),
							},
							RefB: common.DocElementID{
								ElementRefID: toSPDXID(pkg3),
							},
							Relationship:        spdx.RelationshipOther,
							RelationshipComment: "ownership-by-file-overlap: indicates that the parent package claims ownership of a child package since the parent metadata indicates overlap with a location that a cataloger found the child package by",
						},
					},
				},
			},
			want: []artifact.Relationship{
				{
					From: pkg2,
					To:   pkg3,
					Type: artifact.OwnershipByFileOverlapRelationship,
				},
			},
		},
		{
			name: "dependency-of relationship",
			args: args{
				spdxIDMap: map[string]any{
					string(toSPDXID(pkg2)): pkg2,
					string(toSPDXID(pkg3)): pkg3,
				},
				doc: &spdx.Document{
					Relationships: []*spdx.Relationship{
						{
							RefA: common.DocElementID{
								ElementRefID: toSPDXID(pkg2),
							},
							RefB: common.DocElementID{
								ElementRefID: toSPDXID(pkg3),
							},
							Relationship:        spdx.RelationshipDependencyOf,
							RelationshipComment: "dependency-of: indicates that the package in RefA is a dependency of the package in RefB",
						},
					},
				},
			},
			want: []artifact.Relationship{
				{
					From: pkg2,
					To:   pkg3,
					Type: artifact.DependencyOfRelationship,
				},
			},
		},
		{
			name: "dependends-on relationship",
			args: args{
				spdxIDMap: map[string]any{
					string(toSPDXID(pkg2)): pkg2,
					string(toSPDXID(pkg3)): pkg3,
				},
				doc: &spdx.Document{
					Relationships: []*spdx.Relationship{
						{
							RefA: common.DocElementID{
								ElementRefID: toSPDXID(pkg3),
							},
							RefB: common.DocElementID{
								ElementRefID: toSPDXID(pkg2),
							},
							Relationship:        spdx.RelationshipDependsOn,
							RelationshipComment: "dependends-on: indicates that the package in RefA depends on the package in RefB",
						},
					},
				},
			},
			want: []artifact.Relationship{
				{
					From: pkg2,
					To:   pkg3,
					Type: artifact.DependencyOfRelationship,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := toSyftRelationships(tt.args.spdxIDMap, tt.args.doc)
			require.Len(t, actual, len(tt.want))
			for i := range actual {
				require.Equal(t, tt.want[i].From.ID(), actual[i].From.ID())
				require.Equal(t, tt.want[i].To.ID(), actual[i].To.ID())
				require.Equal(t, tt.want[i].Type, actual[i].Type)
			}
		})
	}
}

func Test_convertToAndFromFormat(t *testing.T) {
	packages := []pkg.Package{
		{
			Name: "pkg1",
		},
		{
			Name: "pkg2",
		},
	}

	for i := range packages {
		(&packages[i]).SetID()
	}

	relationships := []artifact.Relationship{
		{
			From: packages[0],
			To:   packages[1],
			Type: artifact.ContainsRelationship,
		},
	}

	tests := []struct {
		name          string
		source        source.Description
		packages      []pkg.Package
		relationships []artifact.Relationship
	}{
		{
			name: "image source",
			source: source.Description{
				ID: "DocumentRoot-Image-some-image",
				Metadata: source.ImageMetadata{
					ID:             "DocumentRoot-Image-some-image",
					UserInput:      "some-image:some-tag",
					ManifestDigest: "sha256:ab8b83234bc28f28d8e",
				},
				Name:    "some-image",
				Version: "some-tag",
			},
			packages:      packages,
			relationships: relationships,
		},
		{
			name: ". directory source",
			source: source.Description{
				ID:   "DocumentRoot-Directory-.",
				Name: ".",
				Metadata: source.DirectoryMetadata{
					Path: ".",
				},
			},
			packages:      packages,
			relationships: relationships,
		},
		{
			name: "directory source",
			source: source.Description{
				ID:   "DocumentRoot-Directory-my-app",
				Name: "my-app",
				Metadata: source.DirectoryMetadata{
					Path: "my-app",
				},
			},
			packages:      packages,
			relationships: relationships,
		},
		{
			name: "file source",
			source: source.Description{
				ID: "DocumentRoot-File-my-app.exe",
				Metadata: source.FileMetadata{
					Path: "my-app.exe",
					Digests: []file.Digest{
						{
							Algorithm: "sha256",
							Value:     "3723cae0b8b83234bc28f28d8e",
						},
					},
				},
				Name: "my-app.exe",
			},
			packages:      packages,
			relationships: relationships,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			src := &test.source
			s := sbom.SBOM{
				Source: *src,
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(test.packages...),
				},
				Relationships: test.relationships,
			}
			doc := ToFormatModel(s)
			got, err := ToSyftModel(doc)
			require.NoError(t, err)

			if diff := cmp.Diff(&s, got,
				cmpopts.IgnoreUnexported(artifact.Relationship{}),
				cmpopts.IgnoreUnexported(file.LocationSet{}),
				cmpopts.IgnoreUnexported(pkg.Collection{}),
				cmpopts.IgnoreUnexported(pkg.Package{}),
				cmpopts.IgnoreUnexported(pkg.LicenseSet{}),
				cmpopts.IgnoreFields(sbom.Artifacts{}, "FileMetadata", "FileDigests"),
			); diff != "" {
				t.Fatalf("packages do not match:\n%s", diff)
			}
		})
	}
}

func Test_purlValue(t *testing.T) {
	tests := []struct {
		purl     packageurl.PackageURL
		expected string
	}{
		{
			purl:     packageurl.PackageURL{},
			expected: "",
		},
		{
			purl: packageurl.PackageURL{
				Name:    "name",
				Version: "version",
			},
			expected: "",
		},
		{
			purl: packageurl.PackageURL{
				Type:    "typ",
				Version: "version",
			},
			expected: "",
		},
		{
			purl: packageurl.PackageURL{
				Type:    "typ",
				Name:    "name",
				Version: "version",
			},
			expected: "pkg:typ/name@version",
		},
		{
			purl: packageurl.PackageURL{
				Type:    "typ",
				Name:    "name",
				Version: "version",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "q",
						Value: "v",
					},
				},
			},
			expected: "pkg:typ/name@version?q=v",
		},
	}

	for _, test := range tests {
		t.Run(test.purl.String(), func(t *testing.T) {
			got := purlValue(test.purl)
			require.Equal(t, test.expected, got)
		})
	}
}

func Test_directPackageFiles(t *testing.T) {
	doc := &spdx.Document{
		SPDXVersion: "SPDX-2.3",
		Packages: []*spdx.Package{
			{
				PackageName:           "some-package",
				PackageSPDXIdentifier: "1",
				PackageVersion:        "1.0.5",
				Files: []*spdx.File{
					{
						FileName:           "some-file",
						FileSPDXIdentifier: "2",
						Checksums: []spdx.Checksum{
							{
								Algorithm: "SHA1",
								Value:     "a8d733c64f9123",
							},
						},
					},
				},
			},
		},
	}

	got, err := ToSyftModel(doc)
	require.NoError(t, err)

	p := pkg.Package{
		Name:    "some-package",
		Version: "1.0.5",
	}
	p.SetID()
	f := file.Location{
		LocationData: file.LocationData{
			Coordinates: file.Coordinates{
				RealPath:     "some-file",
				FileSystemID: "",
			},
			AccessPath: "some-file",
		},
		LocationMetadata: file.LocationMetadata{
			Annotations: map[string]string{},
		},
	}
	s := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(p),
			FileMetadata: map[file.Coordinates]file.Metadata{
				f.Coordinates: {},
			},
			FileDigests: map[file.Coordinates][]file.Digest{
				f.Coordinates: {
					{
						Algorithm: "sha1",
						Value:     "a8d733c64f9123",
					},
				},
			},
		},
		Relationships: []artifact.Relationship{
			{
				From: p,
				To:   f,
				Type: artifact.ContainsRelationship,
			},
		},
		Source:     source.Description{},
		Descriptor: sbom.Descriptor{},
	}

	require.Equal(t, s, got)
}

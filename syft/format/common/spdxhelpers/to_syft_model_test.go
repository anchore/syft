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
				Name:     "some-image",
				Version:  "some-tag",
				Supplier: "some-supplier",
			},
			packages:      packages,
			relationships: relationships,
		},
		{
			name: ". directory source with supplier",
			source: source.Description{
				ID:       "DocumentRoot-Directory-.",
				Name:     ".",
				Supplier: "some-supplier",
				Metadata: source.DirectoryMetadata{
					Path: ".",
				},
			},
			packages:      packages,
			relationships: relationships,
		},
		{
			name: "directory source without supplier",
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
				PackageSPDXIdentifier: "1", // important!
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
	p.OverrideID("1") // the same as the spdxID on the package element
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

func Test_useSPDXIdentifierOverDerivedSyftArtifactID(t *testing.T) {
	doc := &spdx.Document{
		SPDXVersion: "SPDX-2.3",
		Packages: []*spdx.Package{
			{
				PackageName:           "some-package",
				PackageSPDXIdentifier: "1", // important!
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
	s, err := ToSyftModel(doc)

	assert.Nil(t, err)
	assert.NotNil(t, s.Artifacts.Packages.Package("1"))
}

func Test_skipsPackagesWithGeneratedFromRelationship(t *testing.T) {
	doc := &spdx.Document{
		SPDXVersion: "SPDX-2.3",
		Packages: []*spdx.Package{
			{
				PackageName:           "package-1",
				PackageSPDXIdentifier: "1",
				PackageVersion:        "1.0.5",
			},
			{
				PackageName:           "package-1-src",
				PackageSPDXIdentifier: "1-src",
				PackageVersion:        "1.0.5-src",
			},
		},
		Relationships: []*spdx.Relationship{
			{
				Relationship: spdx.RelationshipGeneratedFrom,
				RefA: common.DocElementID{ // package 1
					ElementRefID: spdx.ElementID("1"),
				},
				RefB: common.DocElementID{ // generated from package 1-src
					ElementRefID: spdx.ElementID("1-src"),
				},
			},
		},
	}
	s, err := ToSyftModel(doc)

	assert.Nil(t, err)
	assert.NotNil(t, s.Artifacts.Packages.Package("1"))
	assert.Nil(t, s.Artifacts.Packages.Package("1-src"))
}

func Test_populatePackageLocationsFromRelationships(t *testing.T) {
	tests := []struct {
		name            string
		doc             *spdx.Document
		expectedPkgLocs map[string][]string // package ID -> expected location paths
	}{
		{
			name: "syft-generated SBOM with evident-by relationships",
			doc: &spdx.Document{
				SPDXVersion:    "SPDX-2.3",
				SPDXIdentifier: "DOCUMENT",
				Packages: []*spdx.Package{
					{
						PackageName:           "test-package",
						PackageSPDXIdentifier: "package-1",
						PackageVersion:        "1.0.0",
					},
				},
				Files: []*spdx.File{
					{
						FileName:           "/app/package.json",
						FileSPDXIdentifier: "file-1",
					},
					{
						FileName:           "/app/manifest.txt",
						FileSPDXIdentifier: "file-2",
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "package-1",
						},
						RefB: common.DocElementID{
							ElementRefID: "file-1",
						},
						Relationship:        spdx.RelationshipOther,
						RelationshipComment: "evident-by: indicates the package's existence is evident by the given file",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "package-1",
						},
						RefB: common.DocElementID{
							ElementRefID: "file-2",
						},
						Relationship:        spdx.RelationshipOther,
						RelationshipComment: "evident-by: indicates the package's existence is evident by the given file",
					},
				},
			},
			expectedPkgLocs: map[string][]string{
				"package-1": {"/app/package.json", "/app/manifest.txt"},
			},
		},
		{
			name: "standard SPDX SBOM with CONTAINS relationships",
			doc: &spdx.Document{
				SPDXVersion:    "SPDX-2.3",
				SPDXIdentifier: "DOCUMENT",
				Packages: []*spdx.Package{
					{
						PackageName:           "standard-package",
						PackageSPDXIdentifier: "package-2",
						PackageVersion:        "2.0.0",
					},
				},
				Files: []*spdx.File{
					{
						FileName:           "/usr/bin/app",
						FileSPDXIdentifier: "file-3",
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "package-2",
						},
						RefB: common.DocElementID{
							ElementRefID: "file-3",
						},
						Relationship: spdx.RelationshipContains,
					},
				},
			},
			expectedPkgLocs: map[string][]string{
				"package-2": {"/usr/bin/app"},
			},
		},
		{
			name: "mixed relationships - only location evidence should be processed",
			doc: &spdx.Document{
				SPDXVersion:    "SPDX-2.3",
				SPDXIdentifier: "DOCUMENT",
				Packages: []*spdx.Package{
					{
						PackageName:           "mixed-package",
						PackageSPDXIdentifier: "package-3",
						PackageVersion:        "3.0.0",
					},
				},
				Files: []*spdx.File{
					{
						FileName:           "/opt/config.conf",
						FileSPDXIdentifier: "file-4",
					},
					{
						FileName:           "/opt/readme.txt",
						FileSPDXIdentifier: "file-5",
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "package-3",
						},
						RefB: common.DocElementID{
							ElementRefID: "file-4",
						},
						Relationship: spdx.RelationshipContains,
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "package-3",
						},
						RefB: common.DocElementID{
							ElementRefID: "file-5",
						},
						Relationship:        spdx.RelationshipOther,
						RelationshipComment: "some other relationship comment",
					},
				},
			},
			expectedPkgLocs: map[string][]string{
				"package-3": {"/opt/config.conf"}, // only the CONTAINS relationship should add location
			},
		},
		{
			name: "no location relationships",
			doc: &spdx.Document{
				SPDXVersion:    "SPDX-2.3",
				SPDXIdentifier: "DOCUMENT",
				Packages: []*spdx.Package{
					{
						PackageName:           "no-loc-package",
						PackageSPDXIdentifier: "package-4",
						PackageVersion:        "4.0.0",
					},
				},
				Files: []*spdx.File{
					{
						FileName:           "/var/log/app.log",
						FileSPDXIdentifier: "file-6",
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "package-4",
						},
						RefB: common.DocElementID{
							ElementRefID: "file-6",
						},
						Relationship:        spdx.RelationshipOther,
						RelationshipComment: "unrelated comment",
					},
				},
			},
			expectedPkgLocs: map[string][]string{
				"package-4": {}, // no locations should be added
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert the SPDX document to Syft model
			result, err := ToSyftModel(tt.doc)
			require.NoError(t, err)
			require.NotNil(t, result)

			// Check that packages have the expected locations
			for pkgID, expectedPaths := range tt.expectedPkgLocs {
				pkg := result.Artifacts.Packages.Package(artifact.ID(pkgID))
				require.NotNil(t, pkg, "package %s should exist", pkgID)

				actualPaths := make([]string, 0)
				for _, loc := range pkg.Locations.ToSlice() {
					actualPaths = append(actualPaths, loc.RealPath)
				}

				if len(expectedPaths) == 0 {
					assert.Empty(t, actualPaths, "package %s should have no locations", pkgID)
				} else {
					assert.ElementsMatch(t, expectedPaths, actualPaths,
						"package %s should have expected locations", pkgID)
				}
			}
		})
	}
}

func Test_populatePackageLocationsFromRelationships_duplicateLocations(t *testing.T) {
	doc := &spdx.Document{
		SPDXVersion:    "SPDX-2.3",
		SPDXIdentifier: "DOCUMENT",
		Packages: []*spdx.Package{
			{
				PackageName:           "dup-test-package",
				PackageSPDXIdentifier: "package-dup",
				PackageVersion:        "1.0.0",
			},
		},
		Files: []*spdx.File{
			{
				FileName:           "/same/file.txt",
				FileSPDXIdentifier: "file-dup-1",
			},
			{
				FileName:           "/same/file.txt",
				FileSPDXIdentifier: "file-dup-2",
			},
		},
		Relationships: []*spdx.Relationship{
			{
				RefA: common.DocElementID{
					ElementRefID: "package-dup",
				},
				RefB: common.DocElementID{
					ElementRefID: "file-dup-1",
				},
				Relationship: spdx.RelationshipContains,
			},
			{
				RefA: common.DocElementID{
					ElementRefID: "package-dup",
				},
				RefB: common.DocElementID{
					ElementRefID: "file-dup-2",
				},
				Relationship: spdx.RelationshipContains,
			},
		},
	}

	result, err := ToSyftModel(doc)
	require.NoError(t, err)
	require.NotNil(t, result)

	pkg := result.Artifacts.Packages.Package(artifact.ID("package-dup"))
	require.NotNil(t, pkg)

	// Should only have one location despite two relationships pointing to the same file path
	locations := pkg.Locations.ToSlice()
	assert.Len(t, locations, 1)
	assert.Equal(t, "/same/file.txt", locations[0].RealPath)
}

func Test_licenseFileFiltering(t *testing.T) {
	tests := []struct {
		name             string
		files            []struct{ id, path string }
		expectedIncluded []string // files that should be included as package locations
		expectedExcluded []string // files that should be excluded from package locations
	}{
		{
			name: "license files are excluded from package locations",
			files: []struct{ id, path string }{
				{"file-license-1", "usr/share/licenses/ncurses-base/COPYING"},
				{"file-license-2", "/usr/share/licenses/glibc/LICENSE"},
				{"file-license-3", "/share/licenses/openssl/COPYRIGHT"},
				{"file-binary-1", "/usr/bin/ncurses-app"},
				{"file-config-1", "/etc/ncurses.conf"},
			},
			expectedIncluded: []string{"/usr/bin/ncurses-app", "/etc/ncurses.conf"},
			expectedExcluded: []string{
				"usr/share/licenses/ncurses-base/COPYING",
				"/usr/share/licenses/glibc/LICENSE",
				"/share/licenses/openssl/COPYRIGHT",
			},
		},
		{
			name: "documentation files are excluded from package locations",
			files: []struct{ id, path string }{
				{"file-doc-1", "/usr/share/doc/package/README"},
				{"file-doc-2", "/share/doc/package/CHANGELOG"},
				{"file-doc-3", "/usr/share/man/man1/package.1"},
				{"file-lib-1", "/usr/lib/package/libpackage.so"},
				{"file-bin-1", "/usr/bin/package"},
			},
			expectedIncluded: []string{"/usr/lib/package/libpackage.so", "/usr/bin/package"},
			expectedExcluded: []string{
				"/usr/share/doc/package/README",
				"/share/doc/package/CHANGELOG",
				"/usr/share/man/man1/package.1",
			},
		},
		{
			name: "common license filename patterns are excluded",
			files: []struct{ id, path string }{
				{"file-license-1", "/some/path/COPYING"},
				{"file-license-2", "/another/path/LICENSE.txt"},
				{"file-license-3", "/third/path/LICENCE"},
				{"file-license-4", "/fourth/path/COPYRIGHT"},
				{"file-readme-1", "/some/path/README.md"},
				{"file-changelog-1", "/some/path/CHANGELOG"},
				{"file-legitimate-1", "/usr/bin/app"},
				{"file-legitimate-2", "/etc/config.json"},
			},
			expectedIncluded: []string{"/usr/bin/app", "/etc/config.json"},
			expectedExcluded: []string{
				"/some/path/COPYING",
				"/another/path/LICENSE.txt",
				"/third/path/LICENCE",
				"/fourth/path/COPYRIGHT",
				"/some/path/README.md",
				"/some/path/CHANGELOG",
			},
		},
		{
			name: "case insensitive matching for license filenames",
			files: []struct{ id, path string }{
				{"file-license-1", "/path/copying"},
				{"file-license-2", "/path/license"},
				{"file-license-3", "/path/readme"},
				{"file-legitimate-1", "/usr/bin/copying-tool"},    // should be included
				{"file-legitimate-2", "/usr/lib/licensed-lib.so"}, // should be included
			},
			expectedIncluded: []string{"/usr/bin/copying-tool", "/usr/lib/licensed-lib.so"},
			expectedExcluded: []string{"/path/copying", "/path/license", "/path/readme"},
		},
		{
			name: "mixed file types with comprehensive coverage",
			files: []struct{ id, path string }{
				// License files - should be excluded
				{"file-license-1", "usr/share/licenses/pkg/COPYING"},
				{"file-license-2", "/usr/share/licenses/pkg/LICENSE"},
				// Documentation - should be excluded
				{"file-doc-1", "/usr/share/doc/pkg/README"},
				{"file-doc-2", "/share/man/man1/pkg.1"},
				// Legitimate package files - should be included
				{"file-bin-1", "/usr/bin/pkg"},
				{"file-lib-1", "/usr/lib/pkg/libpkg.so"},
				{"file-config-1", "/etc/pkg/config.conf"},
				{"file-data-1", "/var/lib/pkg/data.db"},
			},
			expectedIncluded: []string{
				"/usr/bin/pkg",
				"/usr/lib/pkg/libpkg.so",
				"/etc/pkg/config.conf",
				"/var/lib/pkg/data.db",
			},
			expectedExcluded: []string{
				"usr/share/licenses/pkg/COPYING",
				"/usr/share/licenses/pkg/LICENSE",
				"/usr/share/doc/pkg/README",
				"/share/man/man1/pkg.1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build SPDX document with the test files
			var spdxFiles []*spdx.File
			var relationships []*spdx.Relationship

			for _, f := range tt.files {
				spdxFiles = append(spdxFiles, &spdx.File{
					FileName:           f.path,
					FileSPDXIdentifier: common.ElementID(f.id),
				})

				// Create CONTAINS relationship from package to file
				relationships = append(relationships, &spdx.Relationship{
					RefA: common.DocElementID{
						ElementRefID: common.ElementID("test-package"),
					},
					RefB: common.DocElementID{
						ElementRefID: common.ElementID(f.id),
					},
					Relationship: spdx.RelationshipContains,
				})
			}

			doc := &spdx.Document{
				SPDXVersion:    "SPDX-2.3",
				SPDXIdentifier: "DOCUMENT",
				Packages: []*spdx.Package{
					{
						PackageName:           "test-package",
						PackageSPDXIdentifier: common.ElementID("test-package"),
						PackageVersion:        "1.0.0",
					},
				},
				Files:         spdxFiles,
				Relationships: relationships,
			}

			// Convert to Syft model
			result, err := ToSyftModel(doc)
			require.NoError(t, err)
			require.NotNil(t, result)

			// Get the test package
			pkg := result.Artifacts.Packages.Package(artifact.ID("test-package"))
			require.NotNil(t, pkg, "test package should exist")

			// Extract actual location paths
			actualPaths := make([]string, 0)
			for _, loc := range pkg.Locations.ToSlice() {
				actualPaths = append(actualPaths, loc.RealPath)
			}

			// Verify that expected files are included
			for _, expectedPath := range tt.expectedIncluded {
				assert.Contains(t, actualPaths, expectedPath,
					"Expected file %s to be included in package locations", expectedPath)
			}

			// Verify that excluded files are NOT included
			for _, excludedPath := range tt.expectedExcluded {
				assert.NotContains(t, actualPaths, excludedPath,
					"Expected file %s to be excluded from package locations", excludedPath)
			}

			// Verify the total count is correct
			assert.Len(t, actualPaths, len(tt.expectedIncluded),
				"Package should have exactly %d locations, got %d: %v",
				len(tt.expectedIncluded), len(actualPaths), actualPaths)
		})
	}
}

func Test_isPackageDiscoveryEvidence(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected bool
	}{
		// License file paths - should be excluded (false)
		{"license file in usr/share/licenses", "usr/share/licenses/pkg/COPYING", false},
		{"license file in share/licenses", "share/licenses/pkg/LICENSE", false},
		{"nested license file", "usr/share/licenses/subpkg/COPYRIGHT", false},

		// Documentation paths - should be excluded (false)
		{"doc file in usr/share/doc", "usr/share/doc/pkg/README", false},
		{"doc file in share/doc", "share/doc/pkg/INSTALL", false},
		{"man page", "usr/share/man/man1/pkg.1", false},
		{"man page in share/man", "share/man/man8/pkg.8", false},

		// License filenames - should be excluded (false)
		{"COPYING file", "some/path/COPYING", false},
		{"LICENSE file", "another/path/LICENSE", false},
		{"LICENCE file", "third/path/LICENCE", false},
		{"COPYRIGHT file", "fourth/path/COPYRIGHT", false},
		{"README file", "some/path/README", false},
		{"CHANGELOG file", "some/path/CHANGELOG", false},
		{"HISTORY file", "some/path/HISTORY", false},
		{"NEWS file", "some/path/NEWS", false},

		// Case insensitive matching
		{"lowercase copying", "path/copying", false},
		{"lowercase license", "path/license", false},
		{"lowercase readme", "path/readme", false},

		// Legitimate package files - should be included (true)
		{"binary executable", "usr/bin/pkg", true},
		{"library file", "usr/lib/pkg/libpkg.so", true},
		{"config file", "etc/pkg/config.conf", true},
		{"data file", "var/lib/pkg/data.db", true},
		{"script file", "usr/share/pkg/scripts/install.sh", true},

		// Edge cases - files with license-like names but in valid contexts
		{"file with copying in name", "usr/bin/copying-tool", true},
		{"file with license in name", "usr/lib/licensed-lib.so", true},
		{"file with readme in name", "usr/bin/readme-viewer", true},

		// Empty or unusual paths
		{"empty path", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPackageDiscoveryEvidence(tt.filePath)
			assert.Equal(t, tt.expected, result,
				"isPackageDiscoveryEvidence(%s) should return %v", tt.filePath, tt.expected)
		})
	}
}

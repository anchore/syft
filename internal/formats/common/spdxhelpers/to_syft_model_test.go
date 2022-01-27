package spdxhelpers

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestToSyftModel(t *testing.T) {
	sbom, err := ToSyftModel(&spdx.Document2_2{
		CreationInfo: &spdx.CreationInfo2_2{
			SPDXVersion:                "1",
			DataLicense:                "GPL",
			SPDXIdentifier:             "id-doc-1",
			DocumentName:               "docName",
			DocumentNamespace:          "docNamespace",
			ExternalDocumentReferences: nil,
			LicenseListVersion:         "",
			CreatorPersons:             nil,
			CreatorOrganizations:       nil,
			CreatorTools:               nil,
			Created:                    "",
			CreatorComment:             "",
			DocumentComment:            "",
		},
		Packages: map[spdx.ElementID]*spdx.Package2_2{
			"id-pkg-1": {
				PackageName:                 "pkg-1",
				PackageSPDXIdentifier:       "id-pkg-1",
				PackageVersion:              "5.4.3",
				PackageSupplierPerson:       "",
				PackageSupplierOrganization: "",
				PackageLicenseDeclared:      "",
				PackageDescription:          "",
				PackageExternalReferences: []*spdx.PackageExternalReference2_2{
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
						Category: "PACKAGE_MANAGER",
						Locator:  "pkg:alpine/pkg-1@5.4.3?arch=x86_64&upstream=p1-origin&distro=alpine-3.10.9",
						RefType:  "purl",
					},
				},
				Files: nil,
			},
			"id-pkg-2": {
				PackageName:                 "pkg-2",
				PackageSPDXIdentifier:       "id-pkg-2",
				PackageVersion:              "7.3.1",
				PackageSupplierPerson:       "",
				PackageSupplierOrganization: "",
				PackageLicenseDeclared:      "",
				PackageDescription:          "",
				PackageExternalReferences: []*spdx.PackageExternalReference2_2{
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
						Category: "PACKAGE_MANAGER",
						Locator:  "pkg:deb/pkg-2@7.3.1?arch=x86_64&upstream=p2-origin@9.1.3&distro=debian-3.10.9",
						RefType:  "purl",
					},
				},
				Files: nil,
			},
		},
		UnpackagedFiles: map[spdx.ElementID]*spdx.File2_2{},
		Relationships:   []*spdx.Relationship2_2{},
	})

	assert.NoError(t, err)

	assert.NotNil(t, sbom)

	pkgs := sbom.Artifacts.PackageCatalog.Sorted()

	assert.Len(t, pkgs, 2)

	p1 := pkgs[0]
	assert.Equal(t, p1.Name, "pkg-1")
	assert.Equal(t, p1.MetadataType, pkg.ApkMetadataType)
	p1meta := p1.Metadata.(pkg.ApkMetadata)
	assert.Equal(t, p1meta.OriginPackage, "p1-origin")
	assert.Len(t, p1.CPEs, 2)

	p2 := pkgs[1]
	assert.Equal(t, p2.Name, "pkg-2")
	assert.Equal(t, p2.MetadataType, pkg.DpkgMetadataType)
	p2meta := p2.Metadata.(pkg.DpkgMetadata)
	assert.Equal(t, p2meta.Source, "p2-origin")
	assert.Equal(t, p2meta.SourceVersion, "9.1.3")
	assert.Len(t, p2.CPEs, 3)
}

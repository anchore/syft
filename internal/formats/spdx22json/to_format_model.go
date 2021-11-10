package spdx22json

import (
	"fmt"
	"time"

	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/formats/common/spdxhelpers"
	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/pkg"
)

// toFormatModel creates and populates a new JSON document struct that follows the SPDX 2.2 spec from the given cataloging results.
func toFormatModel(s sbom.SBOM) model.Document {
	name := spdxhelpers.DocumentName(s.Source)
	packages, files, relationships := extractFromCatalog(s.Artifacts.PackageCatalog)

	return model.Document{
		Element: model.Element{
			SPDXID: model.ElementID("DOCUMENT").String(),
			Name:   name,
		},
		SPDXVersion: model.Version,
		CreationInfo: model.CreationInfo{
			Created: time.Now().UTC(),
			Creators: []string{
				// note: key-value format derived from the JSON example document examples: https://github.com/spdx/spdx-spec/blob/v2.2/examples/SPDXJSONExample-v2.2.spdx.json
				"Organization: Anchore, Inc",
				"Tool: " + internal.ApplicationName + "-" + version.FromBuild().Version,
			},
			LicenseListVersion: spdxlicense.Version,
		},
		DataLicense:       "CC0-1.0",
		DocumentNamespace: spdxhelpers.DocumentNamespace(name, s.Source),
		Packages:          packages,
		Files:             files,
		Relationships:     relationships,
	}
}

func extractFromCatalog(catalog *pkg.Catalog) ([]model.Package, []model.File, []model.Relationship) {
	packages := make([]model.Package, 0)
	relationships := make([]model.Relationship, 0)
	files := make([]model.File, 0)

	for _, p := range catalog.Sorted() {
		license := spdxhelpers.License(p)
		packageSpdxID := model.ElementID(fmt.Sprintf("Package-%+v-%s-%s", p.Type, p.Name, p.Version)).String()

		packageFiles, fileIDs, packageFileRelationships := spdxhelpers.Files(packageSpdxID, p)
		files = append(files, packageFiles...)

		relationships = append(relationships, packageFileRelationships...)

		// note: the license concluded and declared should be the same since we are collecting license information
		// from the project data itself (the installed package files).
		packages = append(packages, model.Package{
			Description:      spdxhelpers.Description(p),
			DownloadLocation: spdxhelpers.DownloadLocation(p),
			ExternalRefs:     spdxhelpers.ExternalRefs(p),
			FilesAnalyzed:    false,
			HasFiles:         fileIDs,
			Homepage:         spdxhelpers.Homepage(p),
			LicenseDeclared:  license, // The Declared License is what the authors of a project believe govern the package
			Originator:       spdxhelpers.Originator(p),
			SourceInfo:       spdxhelpers.SourceInfo(p),
			VersionInfo:      p.Version,
			Item: model.Item{
				LicenseConcluded: license, // The Concluded License field is the license the SPDX file creator believes governs the package
				Element: model.Element{
					SPDXID: packageSpdxID,
					Name:   p.Name,
				},
			},
		})
	}

	return packages, files, relationships
}

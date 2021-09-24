package packages

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/presenter/packages/model/spdx22"
	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// SPDXJsonPresenter is a SPDX presentation object for the syft results (see https://github.com/spdx/spdx-spec)
type SPDXJsonPresenter struct {
	catalog     *pkg.Catalog
	srcMetadata source.Metadata
}

// NewSPDXJSONPresenter creates a new JSON presenter object for the given cataloging results.
func NewSPDXJSONPresenter(catalog *pkg.Catalog, srcMetadata source.Metadata) *SPDXJsonPresenter {
	return &SPDXJsonPresenter{
		catalog:     catalog,
		srcMetadata: srcMetadata,
	}
}

// Present the catalog results to the given writer.
func (pres *SPDXJsonPresenter) Present(output io.Writer) error {
	doc := newSPDXJsonDocument(pres.catalog, pres.srcMetadata)

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}

// newSPDXJsonDocument creates and populates a new JSON document struct that follows the SPDX 2.2 spec from the given cataloging results.
func newSPDXJsonDocument(catalog *pkg.Catalog, srcMetadata source.Metadata) spdx22.Document {
	var name string
	switch srcMetadata.Scheme {
	case source.ImageScheme:
		name = srcMetadata.ImageMetadata.UserInput
	case source.DirectoryScheme:
		name = srcMetadata.Path
	}

	packages, files, relationships := newSPDXJsonElements(catalog)

	return spdx22.Document{
		Element: spdx22.Element{
			SPDXID: spdx22.ElementID("DOCUMENT").String(),
			Name:   name,
		},
		SPDXVersion: spdx22.Version,
		CreationInfo: spdx22.CreationInfo{
			Created: time.Now().UTC(),
			Creators: []string{
				// note: key-value format derived from the JSON example document examples: https://github.com/spdx/spdx-spec/blob/v2.2/examples/SPDXJSONExample-v2.2.spdx.json
				"Organization: Anchore, Inc",
				"Tool: " + internal.ApplicationName + "-" + version.FromBuild().Version,
			},
			LicenseListVersion: spdxlicense.Version,
		},
		DataLicense:       "CC0-1.0",
		DocumentNamespace: fmt.Sprintf("https://anchore.com/syft/image/%s", srcMetadata.ImageMetadata.UserInput),
		Packages:          packages,
		Files:             files,
		Relationships:     relationships,
	}
}

func newSPDXJsonElements(catalog *pkg.Catalog) ([]spdx22.Package, []spdx22.File, []spdx22.Relationship) {
	packages := make([]spdx22.Package, 0)
	relationships := make([]spdx22.Relationship, 0)
	files := make([]spdx22.File, 0)

	for _, p := range catalog.Sorted() {
		license := getSPDXLicense(p)
		packageSpdxID := spdx22.ElementID(fmt.Sprintf("Package-%+v-%s-%s", p.Type, p.Name, p.Version)).String()

		packageFiles, fileIDs, packageFileRelationships := getSPDXFiles(packageSpdxID, p)
		files = append(files, packageFiles...)

		relationships = append(relationships, packageFileRelationships...)

		// note: the license concluded and declared should be the same since we are collecting license information
		// from the project data itself (the installed package files).
		packages = append(packages, spdx22.Package{
			Description:      getSPDXDescription(p),
			DownloadLocation: getSPDXDownloadLocation(p),
			ExternalRefs:     getSPDXExternalRefs(p),
			FilesAnalyzed:    false,
			HasFiles:         fileIDs,
			Homepage:         getSPDXHomepage(p),
			LicenseDeclared:  license, // The Declared License is what the authors of a project believe govern the package
			Originator:       getSPDXOriginator(p),
			SourceInfo:       getSPDXSourceInfo(p),
			VersionInfo:      p.Version,
			Item: spdx22.Item{
				LicenseConcluded: license, // The Concluded License field is the license the SPDX file creator believes governs the package
				Element: spdx22.Element{
					SPDXID: packageSpdxID,
					Name:   p.Name,
				},
			},
		})
	}

	return packages, files, relationships
}

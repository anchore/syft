package packages

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	spdxLicense "github.com/mitchellh/go-spdx"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/presenter/packages/model/spdx_2_2"
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
	doc := newSpdxJsonDocument(pres.catalog, pres.srcMetadata)

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}

func newSpdxJsonDocument(catalog *pkg.Catalog, srcMetadata source.Metadata) spdx_2_2.Document {
	return spdx_2_2.Document{
		SPDXVersion: "SPDX-2.2",
		CreationInfo: spdx_2_2.CreationInfo{
			Comment: "",
			Created: time.Now().UTC(),
			Creators: []string{
				"Anchore, Inc",
				internal.ApplicationName + "-" + version.FromBuild().Version,
			},
			LicenseListVersion: "",
		},
		DataLicense:                "CC0-1.0",
		ExternalDocumentRefs:       nil,
		HasExtractedLicensingInfos: nil,
		// TODO: rethink this
		DocumentNamespace: fmt.Sprintf("https://anchore.com/syft/image/%s", srcMetadata.ImageMetadata.UserInput),
		DocumentDescribes: nil,
		Packages:          newSpdxJsonPackages(catalog),
		Files:             nil,
		Snippets:          nil,
		Element: spdx_2_2.Element{
			// should this be unique to the user's input? or otherwise just say document?
			SPDXID:        spdx_2_2.ElementID("Document").String(),
			Annotations:   nil,
			Comment:       "",
			Name:          srcMetadata.ImageMetadata.UserInput,
			Relationships: nil,
		},
	}
}

func newSpdxJsonPackages(catalog *pkg.Catalog) []spdx_2_2.Package {
	results := make([]spdx_2_2.Package, 0)
	for _, p := range catalog.Sorted() {
		license := "NONE"
		if len(p.Licenses) > 0 {
			// note: we are not supporting complex expressions at this time, only individual licenses
			licenseInfo, err := spdxLicense.License(p.Licenses[0])
			if err != nil {
				log.Warnf("unable to parse SPDX license for package=%+v : %+v", p, err)
				license = "NOASSERTION"
			} else {
				license = licenseInfo.ID
			}
		}

		externalRefs := make([]spdx_2_2.ExternalRef, 0)
		for _, c := range p.CPEs {
			externalRefs = append(externalRefs, spdx_2_2.ExternalRef{
				Comment:           "",
				ReferenceCategory: spdx_2_2.SecurityReferenceCategory,
				ReferenceLocator:  c.BindToFmtString(),
				ReferenceType:     spdx_2_2.Cpe23ExternalRefType,
			})
		}

		if p.PURL != "" {
			externalRefs = append(externalRefs, spdx_2_2.ExternalRef{
				Comment:           "",
				ReferenceCategory: spdx_2_2.PackageManagerReferenceCategory,
				ReferenceLocator:  p.PURL,
				ReferenceType:     spdx_2_2.PurlExternalRefType,
			})
		}

		// note: the license concluded and declared should be the same since we are collecting license information
		// from the project data itself (the installed package files).

		results = append(results, spdx_2_2.Package{
			Checksums:        nil,
			Description:      "",
			DownloadLocation: "",
			ExternalRefs:     externalRefs,
			FilesAnalyzed:    false,
			HasFiles:         nil,
			Homepage:         "",
			// The Declared License is what the authors of a project believe govern the package
			LicenseDeclared:         license,
			Originator:              "",
			PackageFileName:         "",
			PackageVerificationCode: spdx_2_2.PackageVerificationCode{},
			SourceInfo:              "",
			Summary:                 "",
			Supplier:                "",
			VersionInfo:             p.Version,
			Item: spdx_2_2.Item{
				LicenseComments: "",
				// The Concluded License field is the license the SPDX file creator believes governs the package
				LicenseConcluded:     license,
				LicenseInfoFromFiles: nil,
				LicenseInfoInFiles:   nil,
				CopyrightText:        "",
				AttributionTexts:     nil,
				Element: spdx_2_2.Element{
					SPDXID:        spdx_2_2.ElementID(fmt.Sprintf("Package-%+v-%s-%s", p.Type, p.Name, p.Version)).String(),
					Annotations:   nil,
					Comment:       "",
					Name:          p.Name,
					Relationships: nil,
				},
			},
		})
	}
	return results
}

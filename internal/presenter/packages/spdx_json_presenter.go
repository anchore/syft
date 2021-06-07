package packages

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
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
		DocumentNamespace:          fmt.Sprintf("https://anchore.com/syft/image/%s", srcMetadata.ImageMetadata.UserInput),
		Packages:                   newSpdxJsonPackages(catalog),
		Files:                      nil,
		Snippets:                   nil,
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
		license := getLicense(p)

		// note: the license concluded and declared should be the same since we are collecting license information
		// from the project data itself (the installed package files).

		results = append(results, spdx_2_2.Package{
			Description:      getDescription(p),
			DownloadLocation: getDownloadLocation(p),
			ExternalRefs:     getExternalRefs(p),
			FilesAnalyzed:    false,
			Homepage:         getHomepage(p),
			LicenseDeclared:  license, // The Declared License is what the authors of a project believe govern the package
			Originator:       getOriginator(p),
			SourceInfo:       getSourceInfo(p),
			VersionInfo:      p.Version,
			Item: spdx_2_2.Item{
				LicenseConcluded: license, // The Concluded License field is the license the SPDX file creator believes governs the package
				Element: spdx_2_2.Element{
					SPDXID: spdx_2_2.ElementID(fmt.Sprintf("Package-%+v-%s-%s", p.Type, p.Name, p.Version)).String(),
					Name:   p.Name,
				},
			},
		})
	}
	return results
}

func getExternalRefs(p *pkg.Package) (externalRefs []spdx_2_2.ExternalRef) {
	externalRefs = make([]spdx_2_2.ExternalRef, 0)
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
	return externalRefs
}

func getLicense(p *pkg.Package) string {
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
	return license
}

func getDownloadLocation(p *pkg.Package) string {
	switch metadata := p.Metadata.(type) {
	case pkg.ApkMetadata:
		return metadata.URL
	case pkg.NpmPackageJSONMetadata:
		return metadata.URL
	default:
		return ""
	}
}

func getHomepage(p *pkg.Package) string {
	switch metadata := p.Metadata.(type) {
	case pkg.GemMetadata:
		return metadata.Homepage
	case pkg.NpmPackageJSONMetadata:
		return metadata.Homepage
	default:
		return ""
	}
}

func getSourceInfo(p *pkg.Package) string {
	answer := ""
	switch p.Type {
	case pkg.RpmPkg:
		answer = "acquired package info RPM DB"
	case pkg.ApkPkg:
		answer = "acquired package info APK DB"
	case pkg.DebPkg:
		answer = "acquired package info DPKG DB"
	case pkg.NpmPkg:
		answer = "acquired package info from installed node module manifest file"
	case pkg.PythonPkg:
		answer = "acquired package info from installed python package manifest file"
	case pkg.JavaPkg, pkg.JenkinsPluginPkg:
		answer = "acquired package info from installed java archive"
	case pkg.GemPkg:
		answer = "acquired package info from installed gem metadata file"
	case pkg.GoModulePkg:
		answer = "acquired package info from go module metadata file"
	case pkg.RustPkg:
		answer = "acquired package info from rust cargo manifest"
	default:
		answer = "determine from the following paths"
	}
	var paths []string
	for _, l := range p.Locations {
		paths = append(paths, l.RealPath)
	}

	return answer + ": " + strings.Join(paths, ", ")
}

func getOriginator(p *pkg.Package) string {
	switch metadata := p.Metadata.(type) {
	case pkg.ApkMetadata:
		return metadata.Maintainer
	case pkg.NpmPackageJSONMetadata:
		return metadata.Author
	case pkg.PythonPackageMetadata:
		author := metadata.Author
		if author == "" {
			return metadata.AuthorEmail
		}
		if metadata.AuthorEmail != "" {
			author += fmt.Sprintf(" <%s>", metadata.AuthorEmail)
		}
		return author
	case pkg.GemMetadata:
		if len(metadata.Authors) > 0 {
			return metadata.Authors[0]
		}
		return ""
	case pkg.RpmdbMetadata:
		return metadata.Vendor
	case pkg.DpkgMetadata:
		return metadata.Maintainer
	default:
		return ""
	}
}

func getDescription(p *pkg.Package) string {
	switch metadata := p.Metadata.(type) {
	case pkg.ApkMetadata:
		return metadata.Description
	case pkg.NpmPackageJSONMetadata:
		return metadata.Description
	default:
		return ""
	}
}

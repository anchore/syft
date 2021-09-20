package packages

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/presenter/packages/model/spdx22"
	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/pkg"
)

func getSPDXExternalRefs(p *pkg.Package) (externalRefs []spdx22.ExternalRef) {
	externalRefs = make([]spdx22.ExternalRef, 0)
	for _, c := range p.CPEs {
		externalRefs = append(externalRefs, spdx22.ExternalRef{
			ReferenceCategory: spdx22.SecurityReferenceCategory,
			ReferenceLocator:  c.BindToFmtString(),
			ReferenceType:     spdx22.Cpe23ExternalRefType,
		})
	}

	if p.PURL != "" {
		externalRefs = append(externalRefs, spdx22.ExternalRef{
			ReferenceCategory: spdx22.PackageManagerReferenceCategory,
			ReferenceLocator:  p.PURL,
			ReferenceType:     spdx22.PurlExternalRefType,
		})
	}
	return externalRefs
}

func getSPDXFiles(packageSpdxID string, p *pkg.Package) (files []spdx22.File, fileIDs []string, relationships []spdx22.Relationship) {
	files = make([]spdx22.File, 0)
	fileIDs = make([]string, 0)
	relationships = make([]spdx22.Relationship, 0)

	pkgFileOwner, ok := p.Metadata.(pkg.FileOwner)
	if !ok {
		return files, fileIDs, relationships
	}

	for _, ownedFilePath := range pkgFileOwner.OwnedFiles() {
		baseFileName := filepath.Base(ownedFilePath)
		pathHash := sha256.Sum256([]byte(ownedFilePath))
		fileSpdxID := spdx22.ElementID(fmt.Sprintf("File-%s-%x", p.Name, pathHash)).String()

		fileIDs = append(fileIDs, fileSpdxID)

		files = append(files, spdx22.File{
			FileName: ownedFilePath,
			Item: spdx22.Item{
				Element: spdx22.Element{
					SPDXID: fileSpdxID,
					Name:   baseFileName,
				},
			},
		})

		relationships = append(relationships, spdx22.Relationship{
			SpdxElementID:      packageSpdxID,
			RelationshipType:   spdx22.ContainsRelationship,
			RelatedSpdxElement: fileSpdxID,
		})
	}

	return files, fileIDs, relationships
}

func getSPDXLicense(p *pkg.Package) string {
	// source: https://spdx.github.io/spdx-spec/3-package-information/#313-concluded-license
	// The options to populate this field are limited to:
	// A valid SPDX License Expression as defined in Appendix IV;
	// NONE, if the SPDX file creator concludes there is no license available for this package; or
	// NOASSERTION if:
	//   (i) the SPDX file creator has attempted to but cannot reach a reasonable objective determination;
	//   (ii) the SPDX file creator has made no attempt to determine this field; or
	//   (iii) the SPDX file creator has intentionally provided no information (no meaning should be implied by doing so).

	if len(p.Licenses) == 0 {
		return "NONE"
	}

	// take all licenses and assume an AND expression; for information about license expressions see https://spdx.github.io/spdx-spec/appendix-IV-SPDX-license-expressions/
	var parsedLicenses []string
	for _, l := range p.Licenses {
		if value, exists := spdxlicense.ID(l); exists {
			parsedLicenses = append(parsedLicenses, value)
		}
	}

	if len(parsedLicenses) == 0 {
		return "NOASSERTION"
	}

	return strings.Join(parsedLicenses, " AND ")
}

func noneIfEmpty(value string) string {
	if strings.TrimSpace(value) == "" {
		return "NONE"
	}
	return value
}

func getSPDXDownloadLocation(p *pkg.Package) string {
	// 3.7: Package Download Location
	// Cardinality: mandatory, one
	// NONE if there is no download location whatsoever.
	// NOASSERTION if:
	//   (i) the SPDX file creator has attempted to but cannot reach a reasonable objective determination;
	//   (ii) the SPDX file creator has made no attempt to determine this field; or
	//   (iii) the SPDX file creator has intentionally provided no information (no meaning should be implied by doing so).

	switch metadata := p.Metadata.(type) {
	case pkg.ApkMetadata:
		return noneIfEmpty(metadata.URL)
	case pkg.NpmPackageJSONMetadata:
		return noneIfEmpty(metadata.URL)
	default:
		return "NOASSERTION"
	}
}

func getSPDXHomepage(p *pkg.Package) string {
	switch metadata := p.Metadata.(type) {
	case pkg.GemMetadata:
		return metadata.Homepage
	case pkg.NpmPackageJSONMetadata:
		return metadata.Homepage
	default:
		return ""
	}
}

func getSPDXSourceInfo(p *pkg.Package) string {
	answer := ""
	switch p.Type {
	case pkg.RpmPkg:
		answer = "acquired package info from RPM DB"
	case pkg.ApkPkg:
		answer = "acquired package info from APK DB"
	case pkg.DebPkg:
		answer = "acquired package info from DPKG DB"
	case pkg.NpmPkg:
		answer = "acquired package info from installed node module manifest file"
	case pkg.PythonPkg:
		answer = "acquired package info from installed python package manifest file"
	case pkg.JavaPkg, pkg.JenkinsPluginPkg:
		answer = "acquired package info from installed java archive"
	case pkg.GemPkg:
		answer = "acquired package info from installed gem metadata file"
	case pkg.GoModulePkg:
		answer = "acquired package info from go module information"
	case pkg.RustPkg:
		answer = "acquired package info from rust cargo manifest"
	default:
		answer = "acquired package info from the following paths"
	}
	var paths []string
	for _, l := range p.Locations {
		paths = append(paths, l.RealPath)
	}

	return answer + ": " + strings.Join(paths, ", ")
}

func getSPDXOriginator(p *pkg.Package) string {
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

func getSPDXDescription(p *pkg.Package) string {
	switch metadata := p.Metadata.(type) {
	case pkg.ApkMetadata:
		return metadata.Description
	case pkg.NpmPackageJSONMetadata:
		return metadata.Description
	default:
		return ""
	}
}

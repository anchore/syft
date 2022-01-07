package spdxhelpers

import (
	"strings"

	"github.com/spdx/tools-golang/spdx"

	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func ToSyftModel(doc *spdx.Document2_2) (*sbom.SBOM, error) {
	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog: toSyftCatalog(doc.Packages),
		},
	}, nil
}

func toSyftCatalog(pkgs map[spdx.ElementID]*spdx.Package2_2) *pkg.Catalog {
	catalog := pkg.NewCatalog()
	for _, p := range pkgs {
		catalog.Add(toSyftPackage(p))
	}
	return catalog
}

func toSyftPackage(p *spdx.Package2_2) pkg.Package {
	purl := extractPURL(p.PackageExternalReferences)
	sP := pkg.Package{
		Type:     pkg.PackageTypeFromPURL(purl),
		Name:     p.PackageName,
		Version:  p.PackageVersion,
		Licenses: parseLicense(p.PackageLicenseDeclared),
		CPEs:     extractCPEs(p.PackageExternalReferences),
		PURL:     purl,
		Language: pkg.LanguageFromPURL(purl),
	}

	sP.SetID()

	return sP
}

func extractPURL(refs []*spdx.PackageExternalReference2_2) string {
	for _, r := range refs {
		if r.RefType == string(model.PurlExternalRefType) {
			return r.Locator
		}
	}
	return ""
}

func extractCPEs(refs []*spdx.PackageExternalReference2_2) (cpes []pkg.CPE) {
	for _, r := range refs {
		if r.RefType == string(model.Cpe23ExternalRefType) {
			cpe, err := pkg.NewCPE(r.Locator)
			if err != nil {
				log.Warnf("unable to extract SPDX CPE=%q: %+v", r.Locator, err)
				continue
			}
			cpes = append(cpes, cpe)
		}
	}
	return cpes
}

func parseLicense(l string) []string {
	if l == "NOASSERTION" || l == "NONE" {
		return nil
	}
	return strings.Split(l, " AND ")
}

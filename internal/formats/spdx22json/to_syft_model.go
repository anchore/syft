package spdx22json

import (
	"github.com/anchore/syft/internal/formats/common/spdxhelpers"
	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func toSyftModel(doc model.Document) (*sbom.SBOM, error) {
	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog: toSyftCatalog(doc.Packages),
		},
	}, nil
}

func toSyftCatalog(pkgs []model.Package) *pkg.Catalog {
	catalog := pkg.NewCatalog()
	for _, p := range pkgs {
		catalog.Add(toSyftPackage(p))
	}
	return catalog
}

func toSyftPackage(p model.Package) pkg.Package {
	purl := spdxhelpers.ExtractPURL(p.ExternalRefs)
	sP := pkg.Package{
		Type:     pkg.PackageTypeFromPURL(purl),
		Name:     p.Name,
		Version:  p.VersionInfo,
		Licenses: spdxhelpers.ParseLicense(p.LicenseDeclared),
		CPEs:     spdxhelpers.ExtractCPEs(p.ExternalRefs),
		PURL:     purl,
		Language: pkg.LanguageFromPURL(purl),
	}

	sP.SetID()

	return sP
}

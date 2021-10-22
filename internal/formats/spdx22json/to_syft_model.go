package spdx22json

import (
	"strings"

	"github.com/anchore/syft/internal/formats/common/spdxhelpers"
	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// note: this format is LOSSY relative to the syftjson formation, which means that decoding may not provide full syft native models
func toSyftModel(doc model.Document) (*pkg.Catalog, *source.Metadata, *distro.Distro, source.Scope, error) {
	return toSyftCatalog(doc.Packages), doc.SyftSourceData, nil, source.UnknownScope, nil
}

func toSyftCatalog(pkgs []model.Package) *pkg.Catalog {
	catalog := pkg.NewCatalog()
	for _, p := range pkgs {
		catalog.Add(toSyftPackage(p))
	}
	return catalog
}

func toSyftPackage(p model.Package) pkg.Package {
	syftPkg := pkg.Package{
		Name:     p.Name,
		Version:  p.VersionInfo,
		CPEs:     spdxhelpers.ExtractCPEs(p.ExternalRefs),
		PURL:     spdxhelpers.ExtractPURL(p.ExternalRefs),
		Licenses: strings.Split(p.LicenseConcluded, " AND "),
	}

	// if syftPkg.Type == "" && syftPkg.PURL != "" {
	//	// TODO: extract package type from purl --this is useful for ingesting from tools other than syft and is important for grype
	// }

	return syftPkg
}

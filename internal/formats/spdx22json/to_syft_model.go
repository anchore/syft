package spdx22json

import (
	"github.com/anchore/syft/internal/formats/common/spdxhelpers"
	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func toSyftModel(doc model.Document) (*pkg.Catalog, *source.Metadata, *distro.Distro, error) {
	d, err := toSyftDistro(doc.SyftDistroData)
	if err != nil {
		log.Warnf("unable to parse distro info=%+v: %+v", d, err)
		d = nil
	}

	return toSyftCatalog(doc.Packages), doc.SyftSourceData, d, nil
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
		Name:    p.Name,
		Version: p.VersionInfo,
		CPEs:    spdxhelpers.ExtractCPEs(p.ExternalRefs),
		PURL:    spdxhelpers.ExtractPURL(p.ExternalRefs),
	}

	if extra := p.SyftPackageData; extra != nil {
		syftPkg.Type = extra.PackageType
		syftPkg.FoundBy = extra.FoundBy
		syftPkg.Locations = extra.Locations
		syftPkg.Language = extra.Language
		syftPkg.Licenses = extra.Licenses
		syftPkg.MetadataType = extra.MetadataType
		syftPkg.Metadata = extra.Metadata
	}

	//if syftPkg.Type == "" && syftPkg.PURL != "" {
	//	// TODO: extract package type from purl --this is useful for ingesting from tools other than syft and is important for grype
	//}

	return syftPkg
}

func toSyftDistro(d *model.SyftDistroData) (*distro.Distro, error) {
	if d == nil {
		return nil, nil
	}
	newDistro, err := distro.NewDistro(distro.Type(d.Name), d.Version, d.IDLike)
	if err != nil {
		return nil, err
	}
	return &newDistro, nil
}

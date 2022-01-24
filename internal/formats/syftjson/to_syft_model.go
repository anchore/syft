package syftjson

import (
	"github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func toSyftModel(doc model.Document) (*sbom.SBOM, error) {
	dist, err := distro.NewDistro(distro.Type(doc.Distro.Name), doc.Distro.Version, doc.Distro.IDLike)
	if err != nil {
		return nil, err
	}

	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog: toSyftCatalog(doc.Artifacts),
			Distro:         &dist,
		},
		Source: *toSyftSourceData(doc.Source),
	}, nil
}

func toSyftSourceData(s model.Source) *source.Metadata {
	switch s.Type {
	case "directory":
		return &source.Metadata{
			Scheme: source.DirectoryScheme,
			Path:   s.Target.(string),
		}
	case "image":
		return &source.Metadata{
			Scheme:        source.ImageScheme,
			ImageMetadata: s.Target.(source.ImageMetadata),
		}
	}
	return nil
}

func toSyftCatalog(pkgs []model.Package) *pkg.Catalog {
	catalog := pkg.NewCatalog()
	for _, p := range pkgs {
		catalog.Add(toSyftPackage(p))
	}
	return catalog
}

func toSyftPackage(p model.Package) pkg.Package {
	var cpes []pkg.CPE
	for _, c := range p.CPEs {
		value, err := pkg.NewCPE(c)
		if err != nil {
			log.Warnf("excluding invalid CPE %q: %v", c, err)
			continue
		}

		cpes = append(cpes, value)
	}

	return pkg.Package{
		Name:         p.Name,
		Version:      p.Version,
		FoundBy:      p.FoundBy,
		Locations:    p.Locations,
		Licenses:     p.Licenses,
		Language:     p.Language,
		Type:         p.Type,
		CPEs:         cpes,
		PURL:         p.PURL,
		MetadataType: p.MetadataType,
		Metadata:     p.Metadata,
	}
}

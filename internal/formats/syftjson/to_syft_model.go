package syftjson

import (
	"github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func toSyftModel(doc model.Document) (*pkg.Catalog, *source.Metadata, *distro.Distro, source.Scope, error) {
	dist, err := distro.NewDistro(distro.Type(doc.Distro.Name), doc.Distro.Version, doc.Distro.IDLike)
	if err != nil {
		return nil, nil, nil, source.UnknownScope, err
	}

	srcMetadata, scope := toSyftSourceData(doc.Source)

	return toSyftCatalog(doc.Artifacts), srcMetadata, &dist, scope, nil
}

func toSyftSourceData(s model.Source) (*source.Metadata, source.Scope) {
	switch s.Type {
	case "directory":
		return &source.Metadata{
			Scheme: source.DirectoryScheme,
			Path:   s.Target.(string),
		}, source.UnknownScope
	case "image":
		parsedSource := s.Target.(model.ImageSource)
		return &source.Metadata{
			Scheme:        source.ImageScheme,
			ImageMetadata: parsedSource.ImageMetadata,
		}, parsedSource.Scope
	}
	return nil, source.UnknownScope
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
		ID:           pkg.ID(p.ID),
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

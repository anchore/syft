package syftjson

import (
	"github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/google/go-cmp/cmp"
)

func toSyftModel(doc model.Document) (*sbom.SBOM, error) {
	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog:    toSyftCatalog(doc.Artifacts),
			LinuxDistribution: toSyftLinuxRelease(doc.Distro),
		},
		Source:     *toSyftSourceData(doc.Source),
		Descriptor: toSyftDescriptor(doc.Descriptor),
	}, nil
}

func toSyftLinuxRelease(d model.LinuxRelease) *linux.Release {
	if cmp.Equal(d, model.LinuxRelease{}) {
		return nil
	}
	return &linux.Release{
		PrettyName:       d.PrettyName,
		Name:             d.Name,
		ID:               d.ID,
		IDLike:           d.IDLike,
		Version:          d.Version,
		VersionID:        d.VersionID,
		Variant:          d.Variant,
		VariantID:        d.VariantID,
		HomeURL:          d.HomeURL,
		SupportURL:       d.SupportURL,
		BugReportURL:     d.BugReportURL,
		PrivacyPolicyURL: d.PrivacyPolicyURL,
		CPEName:          d.CPEName,
	}
}

func toSyftDescriptor(d model.Descriptor) sbom.Descriptor {
	return sbom.Descriptor{
		Name:          d.Name,
		Version:       d.Version,
		Configuration: d.Configuration,
	}
}

func toSyftSourceData(s model.Source) *source.Metadata {
	switch s.Type {
	case "directory":
		return &source.Metadata{
			Scheme: source.DirectoryScheme,
			Path:   s.Target.(string),
		}
	case "file":
		return &source.Metadata{
			Scheme: source.FileScheme,
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

	var locations = make([]source.Location, len(p.Locations))
	for i, c := range p.Locations {
		locations[i] = source.NewLocationFromCoordinates(c)
	}

	return pkg.Package{
		Name:         p.Name,
		Version:      p.Version,
		FoundBy:      p.FoundBy,
		Locations:    locations,
		Licenses:     p.Licenses,
		Language:     p.Language,
		Type:         p.Type,
		CPEs:         cpes,
		PURL:         p.PURL,
		MetadataType: p.MetadataType,
		Metadata:     p.Metadata,
	}
}

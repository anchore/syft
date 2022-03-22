package syftjson

import (
	"github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/google/go-cmp/cmp"
)

func toSyftModel(doc model.Document) (*sbom.SBOM, error) {
	catalog := toSyftCatalog(doc.Artifacts)

	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog:    catalog,
			LinuxDistribution: toSyftLinuxRelease(doc.Distro),
		},
		Source:        *toSyftSourceData(doc.Source),
		Descriptor:    toSyftDescriptor(doc.Descriptor),
		Relationships: toSyftRelationships(&doc, catalog, doc.ArtifactRelationships),
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

func toSyftRelationships(doc *model.Document, catalog *pkg.Catalog, relationships []model.Relationship) []artifact.Relationship {
	idMap := make(map[string]interface{})

	for _, p := range catalog.Sorted() {
		idMap[string(p.ID())] = p
		for _, l := range p.Locations {
			idMap[string(l.Coordinates.ID())] = l.Coordinates
		}
	}

	for _, f := range doc.Files {
		idMap[f.ID] = f.Location
	}

	var out []artifact.Relationship
	for _, r := range relationships {
		syftRelationship := toSyftRelationship(idMap, r)
		if syftRelationship != nil {
			out = append(out, *syftRelationship)
		}
	}
	return out
}

func toSyftRelationship(idMap map[string]interface{}, relationship model.Relationship) *artifact.Relationship {
	from, ok := idMap[relationship.Parent].(artifact.Identifiable)
	if !ok {
		log.Warnf("relationship mapping from key %s is not a valid artifact.Identifiable type: %+v", relationship.Parent, idMap[relationship.Parent])
		return nil
	}
	to, ok := idMap[relationship.Child].(artifact.Identifiable)
	if !ok {
		log.Warnf("relationship mapping to key %s is not a valid artifact.Identifiable type: %+v", relationship.Child, idMap[relationship.Child])
		return nil
	}
	typ := artifact.RelationshipType(relationship.Type)

	switch typ {
	case artifact.OwnershipByFileOverlapRelationship:
		fallthrough
	case artifact.ContainsRelationship:
	default:
		log.Warnf("unknown relationship type: %s", typ)
		return nil
	}
	return &artifact.Relationship{
		From: from,
		To:   to,
		Type: typ,
		Data: relationship.Metadata,
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
			Scheme: source.DirectoryType,
			Path:   s.Target.(string),
		}
	case "file":
		return &source.Metadata{
			Scheme: source.FileType,
			Path:   s.Target.(string),
		}
	case "image":
		return &source.Metadata{
			Scheme:        source.ImageType,
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

	var locations = make([]file.Location, len(p.Locations))
	for i, c := range p.Locations {
		locations[i] = file.NewLocationFromCoordinates(c)
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

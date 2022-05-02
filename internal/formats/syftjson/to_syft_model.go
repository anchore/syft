package syftjson

import (
	"github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/google/go-cmp/cmp"
)

func toSyftModel(doc model.Document) (*sbom.SBOM, error) {
	idAliases := make(map[string]string)

	catalog := toSyftCatalog(doc.Artifacts, idAliases)

	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog:    catalog,
			LinuxDistribution: toSyftLinuxRelease(doc.Distro),
		},
		Source:        *toSyftSourceData(doc.Source),
		Descriptor:    toSyftDescriptor(doc.Descriptor),
		Relationships: toSyftRelationships(&doc, catalog, doc.ArtifactRelationships, idAliases),
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

func toSyftRelationships(doc *model.Document, catalog *pkg.Catalog, relationships []model.Relationship, idAliases map[string]string) []artifact.Relationship {
	idMap := make(map[string]interface{})

	for _, p := range catalog.Sorted() {
		idMap[string(p.ID())] = p
		locations := p.Locations.ToSlice()
		for _, l := range locations {
			idMap[string(l.Coordinates.ID())] = l.Coordinates
		}
	}

	for _, f := range doc.Files {
		idMap[f.ID] = f.Location
	}

	var out []artifact.Relationship
	for _, r := range relationships {
		syftRelationship := toSyftRelationship(idMap, r, idAliases)
		if syftRelationship != nil {
			out = append(out, *syftRelationship)
		}
	}
	return out
}

func toSyftRelationship(idMap map[string]interface{}, relationship model.Relationship, idAliases map[string]string) *artifact.Relationship {
	id := func(id string) string {
		aliased, ok := idAliases[id]
		if ok {
			return aliased
		}
		return id
	}
	from, ok := idMap[id(relationship.Parent)].(artifact.Identifiable)
	if !ok {
		log.Warnf("relationship mapping from key %s is not a valid artifact.Identifiable type: %+v", relationship.Parent, idMap[relationship.Parent])
		return nil
	}
	to, ok := idMap[id(relationship.Child)].(artifact.Identifiable)
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

func toSyftCatalog(pkgs []model.Package, idAliases map[string]string) *pkg.Catalog {
	catalog := pkg.NewCatalog()
	for _, p := range pkgs {
		catalog.Add(toSyftPackage(p, idAliases))
	}
	return catalog
}

func toSyftPackage(p model.Package, idAliases map[string]string) pkg.Package {
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

	out := pkg.Package{
		Name:         p.Name,
		Version:      p.Version,
		FoundBy:      p.FoundBy,
		Locations:    source.NewLocationSet(locations...),
		Licenses:     p.Licenses,
		Language:     p.Language,
		Type:         p.Type,
		CPEs:         cpes,
		PURL:         p.PURL,
		MetadataType: p.MetadataType,
		Metadata:     p.Metadata,
	}

	// we don't know if this package ID is truly unique, however, we need to trust the user input in case there are
	// external references to it. That is, we can't derive our own ID (using pkg.SetID()) since consumers won't
	// be able to historically interact with data that references the IDs from the original SBOM document being decoded now.
	out.OverrideID(artifact.ID(p.ID))

	// this alias mapping is currently defunct, but could be useful in the future.
	id := string(out.ID())
	if id != p.ID {
		idAliases[p.ID] = id
	}

	return out
}

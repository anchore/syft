package syftjson

import (
	"fmt"

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// TODO: this is export4ed for the use of the power-user command (temp)
func ToFormatModel(s sbom.SBOM, applicationConfig interface{}) model.Document {
	src, err := toSourceModel(s.Source)
	if err != nil {
		log.Warnf("unable to create syft-json source object: %+v", err)
	}

	return model.Document{
		Artifacts:             toPackageModels(s.Artifacts.PackageCatalog),
		ArtifactRelationships: toRelationshipModel(pkg.NewRelationships(s.Artifacts.PackageCatalog)),
		Source:                src,
		Distro:                toDistroModel(s.Artifacts.Distro),
		Descriptor: model.Descriptor{
			Name:          internal.ApplicationName,
			Version:       version.FromBuild().Version,
			Configuration: applicationConfig,
		},
		Schema: model.Schema{
			Version: internal.JSONSchemaVersion,
			URL:     fmt.Sprintf("https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-%s.json", internal.JSONSchemaVersion),
		},
	}
}

func toPackageModels(catalog *pkg.Catalog) []model.Package {
	artifacts := make([]model.Package, 0)
	if catalog == nil {
		return artifacts
	}
	for _, p := range catalog.Sorted() {
		artifacts = append(artifacts, toPackageModel(p))
	}
	return artifacts
}

// toPackageModel crates a new Package from the given pkg.Package.
func toPackageModel(p *pkg.Package) model.Package {
	var cpes = make([]string, len(p.CPEs))
	for i, c := range p.CPEs {
		cpes[i] = c.BindToFmtString()
	}

	// ensure collections are never nil for presentation reasons
	var locations = make([]source.Location, 0)
	if p.Locations != nil {
		locations = p.Locations
	}

	var licenses = make([]string, 0)
	if p.Licenses != nil {
		licenses = p.Licenses
	}

	return model.Package{
		PackageBasicData: model.PackageBasicData{
			ID:        string(p.ID),
			Name:      p.Name,
			Version:   p.Version,
			Type:      p.Type,
			FoundBy:   p.FoundBy,
			Locations: locations,
			Licenses:  licenses,
			Language:  p.Language,
			CPEs:      cpes,
			PURL:      p.PURL,
		},
		PackageCustomData: model.PackageCustomData{
			MetadataType: p.MetadataType,
			Metadata:     p.Metadata,
		},
	}
}

func toRelationshipModel(relationships []artifact.Relationship) []model.Relationship {
	result := make([]model.Relationship, len(relationships))
	for i, r := range relationships {
		result[i] = model.Relationship{
			Parent:   string(r.From),
			Child:    string(r.To),
			Type:     string(r.Type),
			Metadata: r.Data,
		}
	}
	return result
}

// toSourceModel creates a new source object to be represented into JSON.
func toSourceModel(src source.Metadata) (model.Source, error) {
	switch src.Scheme {
	case source.ImageScheme:
		return model.Source{
			Type:   "image",
			Target: src.ImageMetadata,
		}, nil
	case source.DirectoryScheme:
		return model.Source{
			Type:   "directory",
			Target: src.Path,
		}, nil
	default:
		return model.Source{}, fmt.Errorf("unsupported source: %q", src.Scheme)
	}
}

// toDistroModel creates a struct with the Linux distribution to be represented in JSON.
func toDistroModel(d *distro.Distro) model.Distro {
	if d == nil {
		return model.Distro{}
	}

	return model.Distro{
		Name:    d.Name(),
		Version: d.FullVersion(),
		IDLike:  d.IDLike,
	}
}

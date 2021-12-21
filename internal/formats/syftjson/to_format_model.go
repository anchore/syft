package syftjson

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func toFormatModel(s sbom.SBOM) model.Document {
	src, err := toSourceModel(s.Source)
	if err != nil {
		log.Warnf("unable to create syft-json source object: %+v", err)
	}

	return model.Document{
		Artifacts:             toPackageModels(s.Artifacts.PackageCatalog),
		ArtifactRelationships: toRelationshipModel(s.Relationships),
		Files:                 toFile(s),
		Secrets:               toSecrets(s.Artifacts.Secrets),
		Source:                src,
		Distro:                toDistroModel(s.Artifacts.Distro),
		Descriptor:            toDescriptor(s.Descriptor),
		Schema: model.Schema{
			Version: internal.JSONSchemaVersion,
			URL:     fmt.Sprintf("https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-%s.json", internal.JSONSchemaVersion),
		},
	}
}

func toDescriptor(d sbom.Descriptor) model.Descriptor {
	return model.Descriptor{
		Name:          d.Name,
		Version:       d.Version,
		Configuration: d.Configuration,
	}
}

func toSecrets(data map[source.Coordinates][]file.SearchResult) []model.Secrets {
	results := make([]model.Secrets, 0)
	for coordinates, secrets := range data {
		results = append(results, model.Secrets{
			Location: coordinates,
			Secrets:  secrets,
		})
	}

	// sort by real path then virtual path to ensure the result is stable across multiple runs
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Location.RealPath < results[j].Location.RealPath
	})
	return results
}

func toFile(s sbom.SBOM) []model.File {
	results := make([]model.File, 0)
	artifacts := s.Artifacts

	for _, coordinates := range sbom.AllCoordinates(s) {
		var metadata *source.FileMetadata
		if metadataForLocation, exists := artifacts.FileMetadata[coordinates]; exists {
			metadata = &metadataForLocation
		}

		var digests []file.Digest
		if digestsForLocation, exists := artifacts.FileDigests[coordinates]; exists {
			digests = digestsForLocation
		}

		var classifications []file.Classification
		if classificationsForLocation, exists := artifacts.FileClassifications[coordinates]; exists {
			classifications = classificationsForLocation
		}

		var contents string
		if contentsForLocation, exists := artifacts.FileContents[coordinates]; exists {
			contents = contentsForLocation
		}

		results = append(results, model.File{
			ID:              string(coordinates.ID()),
			Location:        coordinates,
			Metadata:        toFileMetadataEntry(coordinates, metadata),
			Digests:         digests,
			Classifications: classifications,
			Contents:        contents,
		})
	}

	// sort by real path then virtual path to ensure the result is stable across multiple runs
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Location.RealPath < results[j].Location.RealPath
	})
	return results
}

func toFileMetadataEntry(coordinates source.Coordinates, metadata *source.FileMetadata) *model.FileMetadataEntry {
	if metadata == nil {
		return nil
	}

	mode, err := strconv.Atoi(fmt.Sprintf("%o", metadata.Mode))
	if err != nil {
		log.Warnf("invalid mode found in file catalog @ location=%+v mode=%q: %+v", coordinates, metadata.Mode, err)
		mode = 0
	}

	return &model.FileMetadataEntry{
		Mode:            mode,
		Type:            metadata.Type,
		LinkDestination: metadata.LinkDestination,
		UserID:          metadata.UserID,
		GroupID:         metadata.GroupID,
		MIMEType:        metadata.MIMEType,
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
func toPackageModel(p pkg.Package) model.Package {
	var cpes = make([]string, len(p.CPEs))
	for i, c := range p.CPEs {
		cpes[i] = pkg.CPEString(c)
	}

	var licenses = make([]string, 0)
	if p.Licenses != nil {
		licenses = p.Licenses
	}

	var coordinates = make([]source.Coordinates, len(p.Locations))
	for i, l := range p.Locations {
		coordinates[i] = l.Coordinates
	}

	return model.Package{
		PackageBasicData: model.PackageBasicData{
			ID:        string(p.ID()),
			Name:      p.Name,
			Version:   p.Version,
			Type:      p.Type,
			FoundBy:   p.FoundBy,
			Locations: coordinates,
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
			Parent:   string(r.From.ID()),
			Child:    string(r.To.ID()),
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
	case source.FileScheme:
		return model.Source{
			Type:   "file",
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

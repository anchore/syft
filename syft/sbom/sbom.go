package sbom

import (
	"sort"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type SBOM struct {
	Artifacts     Artifacts
	Relationships []artifact.Relationship
	Source        source.Metadata
	Descriptor    Descriptor
}

type Artifacts struct {
	PackageCatalog    *pkg.Catalog
	FileMetadata      map[source.Coordinates]source.FileMetadata
	FileDigests       map[source.Coordinates][]file.Digest
	FileContents      map[source.Coordinates]string
	Secrets           map[source.Coordinates][]file.SearchResult
	LinuxDistribution *linux.Release
}

type Descriptor struct {
	Name          string
	Version       string
	Configuration interface{}
}

func (s SBOM) RelationshipsSorted() []artifact.Relationship {
	relationships := s.Relationships
	sort.SliceStable(relationships, func(i, j int) bool {
		if relationships[i].From.ID() == relationships[j].From.ID() {
			if relationships[i].To.ID() == relationships[j].To.ID() {
				return relationships[i].Type < relationships[j].Type
			}
			return relationships[i].To.ID() < relationships[j].To.ID()
		}
		return relationships[i].From.ID() < relationships[j].From.ID()
	})
	return relationships
}

func (s SBOM) AllCoordinates() []source.Coordinates {
	set := source.NewCoordinateSet()
	for coordinates := range s.Artifacts.FileMetadata {
		set.Add(coordinates)
	}
	for coordinates := range s.Artifacts.FileContents {
		set.Add(coordinates)
	}
	for coordinates := range s.Artifacts.FileDigests {
		set.Add(coordinates)
	}
	for _, relationship := range s.Relationships {
		for _, coordinates := range extractCoordinates(relationship) {
			set.Add(coordinates)
		}
	}
	return set.ToSlice()
}

func (s SBOM) RelationshipsForPackage(p pkg.Package) []artifact.Relationship {
	var relationships []artifact.Relationship
	for _, relationship := range s.Relationships {
		if relationship.From.ID() == p.ID() {
			relationships = append(relationships, relationship)
		}
	}
	return relationships
}

func (s SBOM) CoordinatesForPackage(p pkg.Package) []source.Coordinates {
	var coordinates []source.Coordinates
	for _, relationship := range s.RelationshipsForPackage(p) {
		coordinates = append(coordinates, extractCoordinates(relationship)...)
	}
	return coordinates
}

func extractCoordinates(relationship artifact.Relationship) (results []source.Coordinates) {
	if coordinates, exists := relationship.From.(source.Coordinates); exists {
		results = append(results, coordinates)
	}

	if coordinates, exists := relationship.To.(source.Coordinates); exists {
		results = append(results, coordinates)
	}

	return results
}

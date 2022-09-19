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
	Sources       []source.Metadata
	Descriptor    Descriptor
}

type Artifacts struct {
	PackageCatalog      *pkg.Catalog
	FileMetadata        map[source.Coordinates]source.FileMetadata
	FileDigests         map[source.Coordinates][]file.Digest
	FileClassifications map[source.Coordinates][]file.Classification
	FileContents        map[source.Coordinates]string
	Secrets             map[source.Coordinates][]file.SearchResult
	LinuxDistributions  []linux.Release
}

type Descriptor struct {
	Name          string
	Version       string
	Configuration interface{}
}

func (s SBOM) Source(p *pkg.Package) *source.Metadata {
	for _, r := range s.Relationships {
		if r.Type == artifact.SourceRelationship && r.From.ID() == p.ID() {
			s, _ := r.To.(*source.Metadata)
			return s
		}
	}
	return nil
}

func (s SBOM) Distro(p *pkg.Package) *linux.Release {
	for _, r := range s.Relationships {
		if r.Type == artifact.SourceRelationship && r.From.ID() == p.ID() {
			s, _ := r.To.(*linux.Release)
			return s
		}
	}
	return nil
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
	for coordinates := range s.Artifacts.FileClassifications {
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

func extractCoordinates(relationship artifact.Relationship) (results []source.Coordinates) {
	if coordinates, exists := relationship.From.(source.Coordinates); exists {
		results = append(results, coordinates)
	}

	if coordinates, exists := relationship.To.(source.Coordinates); exists {
		results = append(results, coordinates)
	}

	return results
}

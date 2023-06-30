package sbom

import (
	"sort"

	"golang.org/x/exp/slices"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type SBOM struct {
	Artifacts     Artifacts
	Relationships []artifact.Relationship
	Source        source.Description
	Descriptor    Descriptor
}

type Artifacts struct {
	Packages          *pkg.Collection
	FileMetadata      map[file.Coordinates]file.Metadata
	FileDigests       map[file.Coordinates][]file.Digest
	FileContents      map[file.Coordinates]string
	FileLicenses      map[file.Coordinates][]file.License
	Secrets           map[file.Coordinates][]file.SearchResult
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

func (s SBOM) AllCoordinates() []file.Coordinates {
	set := file.NewCoordinateSet()
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

// RelationshipsForPackage returns all relationships for the provided types.
// If no types are provided, all relationships for the package are returned.
func (s SBOM) RelationshipsForPackage(p pkg.Package, rt ...artifact.RelationshipType) []artifact.Relationship {
	if len(rt) == 0 {
		rt = artifact.AllRelationshipTypes()
	}

	var relationships []artifact.Relationship
	for _, relationship := range s.Relationships {
		// check if the relationship is one we're searching for; rt is inclusive
		idx := slices.IndexFunc(rt, func(r artifact.RelationshipType) bool { return relationship.Type == r })
		if relationship.From.ID() == p.ID() && idx != -1 {
			relationships = append(relationships, relationship)
		}
	}

	return relationships
}

// CoordinatesForPackage returns all coordinates for the provided package for provided relationship types
// If no types are provided, all relationship types are considered.
func (s SBOM) CoordinatesForPackage(p pkg.Package, rt ...artifact.RelationshipType) []file.Coordinates {
	var coordinates []file.Coordinates
	for _, relationship := range s.RelationshipsForPackage(p, rt...) {
		cords := extractCoordinates(relationship)
		coordinates = append(coordinates, cords...)
	}
	return coordinates
}

func extractCoordinates(relationship artifact.Relationship) (results []file.Coordinates) {
	if coordinates, exists := relationship.From.(file.Coordinates); exists {
		results = append(results, coordinates)
	}

	if coordinates, exists := relationship.To.(file.Coordinates); exists {
		results = append(results, coordinates)
	}

	return results
}

package sbom

import (
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
	PackageCatalog      *pkg.Catalog
	FileMetadata        map[file.Coordinates]file.Metadata
	FileDigests         map[file.Coordinates][]file.Digest
	FileClassifications map[file.Coordinates][]file.Classification
	FileContents        map[file.Coordinates]string
	Secrets             map[file.Coordinates][]file.SearchResult
	LinuxDistribution   *linux.Release
}

type Descriptor struct {
	Name          string
	Version       string
	Configuration interface{}
}

func AllCoordinates(sbom SBOM) []file.Coordinates {
	set := file.NewCoordinateSet()
	for coordinates := range sbom.Artifacts.FileMetadata {
		set.Add(coordinates)
	}
	for coordinates := range sbom.Artifacts.FileContents {
		set.Add(coordinates)
	}
	for coordinates := range sbom.Artifacts.FileClassifications {
		set.Add(coordinates)
	}
	for coordinates := range sbom.Artifacts.FileDigests {
		set.Add(coordinates)
	}
	for _, relationship := range sbom.Relationships {
		for _, coordinates := range extractCoordinates(relationship) {
			set.Add(coordinates)
		}
	}
	return set.ToSlice()
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

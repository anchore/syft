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
	FileMetadata        map[source.Coordinates]source.FileMetadata
	FileDigests         map[source.Coordinates][]file.Digest
	FileClassifications map[source.Coordinates][]file.Classification
	FileContents        map[source.Coordinates]string
	Secrets             map[source.Coordinates][]file.SearchResult
	LinuxDistribution   *linux.Release
}

type Descriptor struct {
	Name          string
	Version       string
	Configuration interface{}
}

func AllCoordinates(sbom SBOM) []source.Coordinates {
	set := source.NewCoordinateSet()
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

func extractCoordinates(relationship artifact.Relationship) (results []source.Coordinates) {
	if coordinates, exists := relationship.From.(source.Coordinates); exists {
		results = append(results, coordinates)
	}

	if coordinates, exists := relationship.To.(source.Coordinates); exists {
		results = append(results, coordinates)
	}

	return results
}

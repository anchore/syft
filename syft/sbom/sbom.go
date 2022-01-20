package sbom

import (
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/version"
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

func NewSBOM(src source.Source, config *config.Application) SBOM {
	s := SBOM{
		Source: src.Metadata,
		Descriptor: Descriptor{
			Name:          internal.ApplicationName,
			Version:       version.FromBuild().Version,
			Configuration: config,
		},
	}

	var relationships []<-chan artifact.Relationship
	for _, task := range tasks {
		c := make(chan artifact.Relationship)
		relationships = append(relationships, c)

		go runTask(task, &s.Artifacts, src, c, errs)
	}
	s.Relationships = append(s.Relationships, mergeRelationships(relationships...)...)

}

func mergeRelationships(cs ...<-chan artifact.Relationship) (relationships []artifact.Relationship) {
	for _, c := range cs {
		for n := range c {
			relationships = append(relationships, n)
		}
	}

	return relationships
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

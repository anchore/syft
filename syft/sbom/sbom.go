package sbom

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type SBOM struct {
	Artifacts     Artifacts
	Relationships []artifact.Relationship
	Source        source.Metadata
}

type Artifacts struct {
	PackageCatalog      *pkg.Catalog
	FileMetadata        map[source.Coordinates]source.FileMetadata
	FileDigests         map[source.Coordinates][]file.Digest
	FileClassifications map[source.Coordinates][]file.Classification
	FileContents        map[source.Coordinates]string
	Secrets             map[source.Coordinates][]file.SearchResult
	Distro              *distro.Distro
}

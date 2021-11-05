package sbom

import (
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type SBOM struct {
	Artifacts Artifacts
	Source    source.Metadata
}

type Artifacts struct {
	PackageCatalog      *pkg.Catalog
	FileMetadata        map[source.Location]source.FileMetadata
	FileDigests         map[source.Location][]file.Digest
	FileClassifications map[source.Location][]file.Classification
	FileContents        map[source.Location]string
	Secrets             map[source.Location][]file.SearchResult
	Distro              *distro.Distro
}

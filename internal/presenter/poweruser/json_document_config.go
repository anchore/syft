package poweruser

import (
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type JSONDocumentConfig struct {
	ApplicationConfig config.Application
	PackageCatalog    *pkg.Catalog
	FileMetadata      map[source.Location]source.FileMetadata
	FileDigests       map[source.Location][]file.Digest
	Secrets           map[source.Location][]file.SearchResult
	Distro            *distro.Distro
	SourceMetadata    source.Metadata
}

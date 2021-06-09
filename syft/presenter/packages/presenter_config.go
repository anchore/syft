package packages

import (
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type PresenterConfig struct {
	SourceMetadata source.Metadata
	Catalog        *pkg.Catalog
	Distro         *distro.Distro
	Scope          source.Scope
}

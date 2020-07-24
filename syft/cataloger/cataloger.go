package cataloger

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

type Cataloger interface {
	Name() string
	// TODO: add ID / Name for catalog for uniquely identifying this cataloger type
	SelectFiles(scope.FileResolver) []file.Reference
	// NOTE: one of the errors which is returned is "IterationNeeded", which indicates to the driver to
	// continue with another Select/Catalog pass
	Catalog(map[file.Reference]string) ([]pkg.Package, error)
}

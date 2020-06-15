package cataloger

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/tree"
)

type Cataloger interface {
	Name() string
	// TODO: add ID / Name for catalog for uniquely identifying this cataloger type
	SelectFiles([]tree.FileTreeReader) []file.Reference
	// NOTE: one of the errors which is returned is "IterationNeeded", which indicates to the driver to
	// continue with another Select/Catalog pass
	Catalog(map[file.Reference]string) ([]pkg.Package, error)
}

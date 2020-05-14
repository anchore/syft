package analyzer

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/stereoscope/pkg/file"
)

type Analyzer interface {
	SelectFiles(scope.Scope) []file.Reference
	// NOTE: one of the errors which is returned is "IterationNeeded", which indicates to the driver to
	// continue with another Select/Analyze pass
	Analyze(pkg.CatalogWriter, map[file.Reference]string) error
}

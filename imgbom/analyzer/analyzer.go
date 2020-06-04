package analyzer

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/tree"
)

type Analyzer interface {
	Name() string
	// TODO: add ID / Name for analyze for uniquely identifying this analyzer type
	SelectFiles([]tree.FileTreeReader) []file.Reference
	// NOTE: one of the errors which is returned is "IterationNeeded", which indicates to the driver to
	// continue with another Select/Analyze pass
	Analyze(map[file.Reference]string) ([]pkg.Package, error)
}

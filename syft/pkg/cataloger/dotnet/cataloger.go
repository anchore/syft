package dotnet

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "dotnet-deps-cataloger"

// NewDotnetDepsCataloger returns a new Dotnet cataloger object base on deps json files.
func NewDotnetDepsCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseDotnetDeps, "**/*.deps.json")
}

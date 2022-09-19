package dotnet

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewDotnetDepsCataloger returns a new Dotnet cataloger object base on deps json files.
func NewDotnetDepsCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/*.deps.json": parseDotnetDeps,
	}

	return common.NewGenericCataloger(nil, globParsers, "dotnet-deps-cataloger")
}

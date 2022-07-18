package haskell

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewHackageCataloger returns a new Haskell cataloger object.
func NewHackageCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/stack.yaml":           parseStackYaml,
		"**/stack.yaml.lock":      parseStackLock,
		"**/cabal.project.freeze": parseCabalFreeze,
	}
	return common.NewGenericCataloger(nil, globParsers, "hackage-cataloger")
}

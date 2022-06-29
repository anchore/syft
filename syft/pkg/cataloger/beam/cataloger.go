package beam

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewBeamCataloger returns a new cataloger BeamVM (Elixir/Erlang) object based on detection of Hex based packages.
// func NewBeamCataloger() *common.GenericCataloger {
// 	globParsers := map[string]common.ParserFn{
// 		"**/mix.exs": parseMixExs,
// 	}

// 	return common.NewGenericCataloger(nil, globParsers, "beam-package-cataloger")
// }

// NewBeamLockCataloger returns a new BeamVM (Elixir/Erlang) cataloger object base on Mix & Rebar3 lock files.
func NewBeamLockCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/mix.lock": parseMixLock,
	}

	return common.NewGenericCataloger(nil, globParsers, "beam-lock-cataloger")
}

package beam

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewBeamLockCataloger returns a new BeamVM (Elixir/Erlang) cataloger object base on Mix & Rebar3 lock files.
func NewBeamLockCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/mix.lock":   parseMixLock,
		"**/rebar.lock": parseRebarLock,
	}

	return common.NewGenericCataloger(nil, globParsers, "beam-lock-cataloger")
}

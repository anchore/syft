package haskell

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// TODO: it seems that the stack.yaml/stack.lock/cabal.project.freeze have different purposes and could have different installation intentions
// (some describe intent and are meant to be used by a tool to resolve more dependencies while others describe the actual installed state).
// This hints at splittin these into multiple catalogers, but for now we'll keep them together.

// NewHackageCataloger returns a new Haskell cataloger object.
func NewHackageCataloger() *generic.Cataloger {
	return generic.NewCataloger("haskell-cataloger").
		WithParserByBasename(parseStackYaml, "stack.yaml").
		WithParserByBasename(parseStackLock, "stack.yaml.lock").
		WithParserByBasename(parseCabalFreeze, "cabal.project.freeze")
}

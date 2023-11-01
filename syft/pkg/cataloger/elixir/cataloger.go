/*
Package elixir provides a concrete Cataloger implementation for elixir specific package manger files.
*/
package elixir

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "elixir-mix-lock-cataloger"

// NewMixLockCataloger returns a cataloger object for Elixir mix.lock files.
func NewMixLockCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseMixLock, "**/mix.lock")
}

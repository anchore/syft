/*
Package erlang provides a concrete Cataloger implementation for erlang specific package manger files.
*/
package erlang

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "erlang-rebar-lock-cataloger"

// NewRebarLockCataloger returns parses rebar.lock files and returns packages.
func NewRebarLockCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseRebarLock, "**/rebar.lock")
}

/*
Package ocaml provides a concrete Cataloger implementation for packages relating to the OCaml language ecosystem.
*/
package ocaml

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewPackageCataloger returns a new cataloger object for Lua ROck.
func NewPackageCataloger() pkg.Cataloger {
	return generic.NewCataloger("lua-rock-cataloger").
		WithParserByGlobs(parseOpamPackage, "*opam")
}

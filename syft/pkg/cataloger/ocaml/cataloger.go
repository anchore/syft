/*
Package ocaml provides a concrete Cataloger implementation for packages relating to the OCaml language ecosystem.
*/
package ocaml

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewOpamPackageManagerCataloger returns a new cataloger object for declared OCaml opam packages: package
// definitions (`<name>.opam` and `opam` files) and lock files (`<name>.opam.locked`).
func NewOpamPackageManagerCataloger() pkg.Cataloger {
	return generic.NewCataloger("opam-cataloger").
		WithParserByGlobs(parseOpamPackage, "**/*.opam", "**/opam").
		WithParserByGlobs(parseOpamLockFile, "**/*.opam.locked")
}

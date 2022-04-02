/*
Package rust provides a concrete Cataloger implementation for Cargo.lock files.
*/
package rust

import (
	"github.com/anchore/syft/syft/cataloger/packages/generic"
)

// NewCargoLockCataloger returns a new Rust Cargo lock file cataloger object.
func NewCargoLockCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/Cargo.lock": parseCargoLock,
	}

	return generic.NewCataloger(nil, globParsers, "rust-cataloger")
}

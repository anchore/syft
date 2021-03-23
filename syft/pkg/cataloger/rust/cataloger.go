/*
Package rust provides a concrete Cataloger implementation for Cargo.lock files.
*/
package rust

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewCargoLockCataloger returns a new Rust Cargo lock file cataloger object.
func NewCargoLockCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/Cargo.lock": parseCargoLock,
	}

	return common.NewGenericCataloger(nil, globParsers, "rust-cataloger")
}

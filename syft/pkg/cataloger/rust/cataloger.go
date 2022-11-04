/*
Package rust provides a concrete Cataloger implementation for Cargo.lock files.
*/
package rust

import (
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewCargoLockCataloger returns a new Rust Cargo lock file cataloger object.
func NewCargoLockCataloger() *generic.Cataloger {
	return generic.NewCataloger("rust-cargo-lock-cataloger").
		WithParserByGlobs(parseCargoLock, "**/Cargo.lock")
}

// NewAuditBinaryCataloger returns a new Rust auditable binary cataloger object that can detect dependencies
// in binaries produced with https://github.com/Shnatsel/rust-audit
func NewAuditBinaryCataloger() *generic.Cataloger {
	return generic.NewCataloger("cargo-auditable-binary-cataloger").
		WithParserByMimeTypes(parseAuditBinary, internal.ExecutableMIMETypeSet.List()...)
}

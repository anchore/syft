/*
Package rust provides a concrete Cataloger implementation relating to packages within the Rust language ecosystem.
*/
package rust

import (
	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/rust"
)

// NewCargoLockCataloger returns a new Rust Cargo lock file cataloger object.
func NewCargoLockCataloger(cfg rust.CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger("rust-cargo-lock-cataloger").
		WithParserByGlobs(newCargoModCataloger(cfg).parseCargoLock, "**/Cargo.lock")
}

// NewAuditBinaryCataloger returns a new Rust auditable binary cataloger object that can detect dependencies
// in binaries produced with https://github.com/Shnatsel/rust-audit
func NewAuditBinaryCataloger() pkg.Cataloger {
	return generic.NewCataloger("cargo-auditable-binary-cataloger").
		WithParserByMimeTypes(parseAuditBinary, mimetype.ExecutableMIMETypeSet.List()...)
}

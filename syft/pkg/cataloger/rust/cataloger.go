/*
Package rust provides a concrete Cataloger implementation relating to packages within the Rust language ecosystem.
*/
package rust

import (
	"fmt"

	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	toolName                      = "syft" // used for the user-agent string.
	cargoAuditBinaryCatalogerName = "rust-cargo-auditable-binary-cataloger"
	cargoLockCatalogerName        = "rust-cargo-lock-cataloger"
)

var (
	userAgent = fmt.Sprintf("%s/%s", toolName, syftVersion())
)

// NewCargoLockCataloger returns a new Rust Cargo lock file cataloger object.
func NewCargoLockCataloger(opts CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger(cargoLockCatalogerName).
		WithParserByGlobs(parseCargoLock, "**/Cargo.lock")
}

// NewAuditBinaryCataloger returns a new Rust auditable binary cataloger object that can detect dependencies
// in binaries produced with https://github.com/Shnatsel/rust-audit
func NewAuditBinaryCataloger(opts CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger(cargoAuditBinaryCatalogerName).
		WithParserByMimeTypes(newCargoAuditBinaryCataloger(opts).parseAuditBinary, mimetype.ExecutableMIMETypeSet.List()...)
}

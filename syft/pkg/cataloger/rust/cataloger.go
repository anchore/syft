/*
Package rust provides a concrete Cataloger implementation relating to packages within the Rust language ecosystem.
*/
package rust

import (
	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

type CargoLockCatalogerConfig struct {
	// Todo: find a way to replicate cargo's mapping from repository source to their repository dir name
	//		When that's done we could enable LocalModCacheDir to point to cargo's cache and read directly from there
	// SearchLocalModCacheLicenses bool   `yaml:"search-local-mod-cache-licenses" json:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`
	// LocalModCacheDir            string `yaml:"local-mod-cache-dir" json:"local-mod-cache-dir" mapstructure:"local-mod-cache-dir"`
	SearchRemote bool `yaml:"search-remote" json:"search-remote" mapstructure:"search-remote"`
}

func DefaultCargoLockCatalogerConfig() CargoLockCatalogerConfig {
	return CargoLockCatalogerConfig{
		// SearchLocalModCacheLicenses: true,
		// LocalModCacheDir:            "~/.cargo/registry",
		SearchRemote: false,
	}
}

// NewCargoLockCataloger returns a new Rust Cargo lock file cataloger object.
func NewCargoLockCataloger(cfg CargoLockCatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger("rust-cargo-lock-cataloger").
		WithParserByGlobs(newCargoModCataloger(cfg).parseCargoLock, "**/Cargo.lock").
		WithProcessors(dependency.Processor(cargoLockDependencySpecifier))
}

// NewAuditBinaryCataloger returns a new Rust auditable binary cataloger object that can detect dependencies
// in binaries produced with https://github.com/Shnatsel/rust-audit
func NewAuditBinaryCataloger() pkg.Cataloger {
	return generic.NewCataloger("cargo-auditable-binary-cataloger").
		WithParserByMimeTypes(parseAuditBinary, mimetype.ExecutableMIMETypeSet.List()...)
}

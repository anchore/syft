package pkg

// RustCargoLockEntry represents a locked dependency from a Cargo.lock file with precise version and checksum information.
type RustCargoLockEntry struct {
	// Name is crate name as specified in Cargo.toml
	Name string `toml:"name" json:"name"`

	// Version is crate version as specified in Cargo.toml
	Version string `toml:"version" json:"version"`

	// Source is the source registry or repository URL in format "registry+https://github.com/rust-lang/crates.io-index" for registry packages
	Source string `toml:"source" json:"source"`

	// Checksum is content checksum for registry packages only (hexadecimal string). Cargo doesn't require or include checksums for git dependencies. Used to detect MITM attacks by verifying downloaded crate matches lockfile checksum.
	Checksum string `toml:"checksum" json:"checksum"`

	// Dependencies are the list of dependencies with version constraints
	Dependencies []string `toml:"dependencies" json:"dependencies"`
}

// RustBinaryAuditEntry represents Rust crate metadata extracted from a compiled binary using cargo-auditable format.
type RustBinaryAuditEntry struct {
	// Name is crate name as specified in audit section of the build binary
	Name string `toml:"name" json:"name"`

	// Version is crate version as specified in audit section of the build binary
	Version string `toml:"version" json:"version"`

	// Source is the source registry or repository where this crate came from
	Source string `toml:"source" json:"source"`
}

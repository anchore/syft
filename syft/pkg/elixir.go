package pkg

// ElixirMixLockEntry is a struct that represents a single entry in a mix.lock file
type ElixirMixLockEntry struct {
	// Name is the package name as found in the mix.lock file
	Name string `mapstructure:"name" json:"name"`

	// Version is the package version as found in the mix.lock file
	Version string `mapstructure:"version" json:"version"`

	// PkgHash is the outer checksum (SHA-256) of the entire Hex package tarball for integrity verification (preferred method, replaces deprecated inner checksum)
	PkgHash string `mapstructure:"pkgHash" json:"pkgHash"`

	// PkgHashExt is the extended package hash format (inner checksum is deprecated - SHA-256 of concatenated file contents excluding CHECKSUM file, now replaced by outer checksum)
	PkgHashExt string `mapstructure:"pkgHashExt" json:"pkgHashExt"`
}

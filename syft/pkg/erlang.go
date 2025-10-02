package pkg

// ErlangRebarLockEntry represents a single package entry from the "deps" section within an Erlang rebar.lock file.
type ErlangRebarLockEntry struct {
	// Name is the package name as found in the rebar.lock file
	Name string `mapstructure:"name" json:"name"`

	// Version is the package version as found in the rebar.lock file
	Version string `mapstructure:"version" json:"version"`

	// PkgHash is the outer checksum (SHA-256) of the entire Hex package tarball for integrity verification (preferred method over deprecated inner checksum)
	PkgHash string `mapstructure:"pkgHash" json:"pkgHash"`

	// PkgHashExt is the extended package hash format (inner checksum deprecated - was SHA-256 of concatenated file contents)
	PkgHashExt string `mapstructure:"pkgHashExt" json:"pkgHashExt"`
}

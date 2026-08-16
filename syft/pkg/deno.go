package pkg

// DenoLockEntry is a struct that rep a single entry found in the "packages" section of a Deno deno.lock file
type DenoLockEntry struct {
	// Integrity is the crpto hash of the package content for verification
	Integrity string `mapstructure:"integrity" json:"integrity"`

	// Dependencies is the list of package specifiers that this package depends on
	Dependencies []string `mapstructure:"dependencies" json:"dependencies"`
}

// DenoRemoteLockEntry is a struct that rep a single entry found in the "remote" section of a Deno deno.lock file
type DenoRemoteLockEntry struct {
	// URL is the remote URL from which the module fetcef
	URL string `mapstructure:"url" json:"url"`

	// Integrity is the crpto hash of the package content for verification
	Integrity string `mapstructure:"integrity" json:"integrity"`
}

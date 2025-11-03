package pkg

// OpamPackage represents an OCaml package managed by the OPAM package manager with metadata from .opam files.
type OpamPackage struct {
	// Name is the package name as found in the .opam file
	Name string `toml:"name" json:"name"`

	// Version is the package version as found in the .opam file
	Version string `toml:"version" json:"version"`

	// Licenses are the list of applicable licenses
	Licenses []string `mapstructure:"licenses" json:"licenses"`

	// URL is download URL for the package source
	URL string `mapstructure:"url" json:"url"`

	// Checksums are the list of checksums for verification
	Checksums []string `mapstructure:"checksums" json:"checksum"`

	// Homepage is project homepage URL
	Homepage string `json:"homepage"`

	// Dependencies are the list of required dependencies
	Dependencies []string `toml:"dependencies" json:"dependencies"`
}

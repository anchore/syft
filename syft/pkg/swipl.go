package pkg

// SwiplPackEntry represents a SWI-Prolog package from the pack system with metadata about the package and its dependencies.
type SwiplPackEntry struct {
	// Name is the package name as found in the .toml file
	Name string `toml:"name" json:"name"`

	// Version is the package version as found in the .toml file
	Version string `toml:"version" json:"version"`

	// Author is author name
	Author string `json:"author" mapstructure:"Author"`

	// AuthorEmail is author email address
	AuthorEmail string `json:"authorEmail" mapstructure:"AuthorEmail"`

	// Packager is packager name (if different from author)
	Packager string `json:"packager" mapstructure:"Packager"`

	// PackagerEmail is packager email address
	PackagerEmail string `json:"packagerEmail" mapstructure:"PackagerEmail"`

	// Homepage is project homepage URL
	Homepage string `json:"homepage"`

	// Dependencies are the list of required dependencies
	Dependencies []string `toml:"dependencies" json:"dependencies"`
}

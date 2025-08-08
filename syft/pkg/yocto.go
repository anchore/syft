package pkg

// YoctoMetadata represents metadata for Yocto/OpenEmbedded packages
type YoctoMetadata struct {
	// Name is the recipe name
	Name string `mapstructure:"name" json:"name"`

	// Version is the package version
	Version string `mapstructure:"version" json:"version"`

	// License is the package license
	License string `mapstructure:"license" json:"license,omitempty"`

	// Layer is the meta layer containing the recipe
	Layer string `mapstructure:"layer" json:"layer,omitempty"`

	// Recipe is the recipe file path
	Recipe string `mapstructure:"recipe" json:"recipe,omitempty"`

	// Epoch is the package epoch
	Epoch string `mapstructure:"epoch" json:"epoch,omitempty"`

	// Release is the package release
	Release string `mapstructure:"release" json:"release,omitempty"`

	// Machine is the target machine architecture
	Machine string `mapstructure:"machine" json:"machine,omitempty"`

	// Source is the source URL or path
	Source string `mapstructure:"source" json:"source,omitempty"`

	// Dependencies is a list of package dependencies
	Dependencies []string `mapstructure:"dependencies" json:"dependencies,omitempty"`
}

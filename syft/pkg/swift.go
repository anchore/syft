package pkg

// SwiftPackageManagerResolvedEntry represents a resolved dependency from a Package.resolved file with its locked version and source location.
type SwiftPackageManagerResolvedEntry struct {
	// Revision is git commit hash of the resolved package
	Revision string `mapstructure:"revision" json:"revision"`
}

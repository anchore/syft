package pkg

// JuliaManifestEntry represents a Julia package from a Manifest.toml lockfile.
type JuliaManifestEntry struct {
	// UUID is the unique identifier for the package
	UUID string `toml:"uuid" json:"uuid"`

	// Deps are the dependency names for this package
	Deps []string `toml:"deps" json:"deps,omitempty"`

	// Path is the local filesystem path for developed packages
	Path string `toml:"path" json:"path,omitempty"`

	// DependencyKind categorizes the dependency: runtime, test, or optional
	DependencyKind string `json:"dependencyKind,omitempty"`
}

package pkg

// LuaRocksPackage represents a Lua package managed by the LuaRocks package manager with metadata from .rockspec files.
type LuaRocksPackage struct {
	// Name is the package name as found in the .rockspec file
	Name string `json:"name"`

	// Version is the package version as found in the .rockspec file
	Version string `json:"version"`

	// License is license identifier
	License string `json:"license"`

	// Homepage is project homepage URL
	Homepage string `json:"homepage"`

	// Description is a human-readable package description
	Description string `json:"description"`

	// URL is the source download URL
	URL string `json:"url"`

	// Dependencies are the map of dependency names to version constraints
	Dependencies map[string]string `json:"dependencies"`
}

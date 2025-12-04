package pkg

// DotnetDepsEntry is a struct that represents a single entry found in the "libraries" section in a .NET [*.]deps.json file.
type DotnetDepsEntry struct {
	// Name is the package name as found in the deps.json file
	Name string `mapstructure:"name" json:"name"`

	// Version is the package version as found in the deps.json file
	Version string `mapstructure:"version" json:"version"`

	// Path is the relative path to the package within the deps structure (e.g. "app.metrics/3.0.0")
	Path string `mapstructure:"path" json:"path"`

	// Sha512 is the SHA-512 hash of the NuGet package content WITHOUT the signed content for verification (won't match hash from NuGet API or manual calculation of .nupkg file)
	Sha512 string `mapstructure:"sha512" json:"sha512"`

	// HashPath is the relative path to the .nupkg.sha512 hash file (e.g. "app.metrics.3.0.0.nupkg.sha512")
	HashPath string `mapstructure:"hashPath" json:"hashPath"`

	// Type is type of entry could be package or project for internal refs
	Type string `mapstructure:"type" json:"type,omitempty"`

	// Executables are the map of .NET Portable Executable files within this package with their version resources
	Executables map[string]DotnetPortableExecutableEntry `json:"executables,omitempty"`
}

// DotnetPackagesLockEntry is a struct that represents a single entry found in the "dependencies" section in a .NET packages.lock.json file.
type DotnetPackagesLockEntry struct {
	// Name is the package name as found in the packages.lock.json file
	Name string `mapstructure:"name" json:"name"`

	// Version is the package version as found in the packages.lock.json file
	Version string `mapstructure:"version" json:"version"`

	// ContentHash is the hash of the package content for verification
	ContentHash string `mapstructure:"contentHash" json:"contentHash"`

	// Type is the dependency type indicating how this dependency was added (Direct=explicit in project file, Transitive=pulled in by another package, Project=project reference)
	Type string `mapstructure:"type" json:"type"`
}

// DotnetPortableExecutableEntry is a struct that represents a single entry found within "VersionResources" section of a .NET Portable Executable binary file.
type DotnetPortableExecutableEntry struct {
	// AssemblyVersion is the .NET assembly version number (strong-named version)
	AssemblyVersion string `json:"assemblyVersion"`

	// LegalCopyright is the copyright notice string
	LegalCopyright string `json:"legalCopyright"`

	// Comments are additional comments or description embedded in PE resources
	Comments string `json:"comments,omitempty"`

	// InternalName is the internal name of the file
	InternalName string `json:"internalName,omitempty"`

	// CompanyName is the company that produced the file
	CompanyName string `json:"companyName"`

	// ProductName is the name of the product this file is part of
	ProductName string `json:"productName"`

	// ProductVersion is the version of the product (may differ from AssemblyVersion)
	ProductVersion string `json:"productVersion"`
}

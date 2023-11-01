package pkg

// DotnetDepsEntry is a struct that represents a single entry found in the "libraries" section in a .NET [*.]deps.json file.
type DotnetDepsEntry struct {
	Name     string `mapstructure:"name" json:"name"`
	Version  string `mapstructure:"version" json:"version"`
	Path     string `mapstructure:"path" json:"path"`
	Sha512   string `mapstructure:"sha512" json:"sha512"`
	HashPath string `mapstructure:"hashPath" json:"hashPath"`
}

// DotnetPortableExecutableEntry is a struct that represents a single entry found within "VersionResources" section of a .NET Portable Executable binary file.
type DotnetPortableExecutableEntry struct {
	AssemblyVersion string `json:"assemblyVersion"`
	LegalCopyright  string `json:"legalCopyright"`
	Comments        string `json:"comments,omitempty"`
	InternalName    string `json:"internalName,omitempty"`
	CompanyName     string `json:"companyName"`
	ProductName     string `json:"productName"`
	ProductVersion  string `json:"productVersion"`
}

package pkg

// NpmPackageJsonMetadata holds extra information that is used in pkg.Package
type NpmPackageJsonMetadata struct {
	Name        string   `mapstructure:"name" json:"name"`
	Version     string   `mapstructure:"version" json:"version"`
	Files       []string `mapstructure:"files" json:"files"`
	Author      string   `mapstructure:"author" json:"author"`
	License     string   `mapstructure:"license" json:"license"`
	Homepage    string   `mapstructure:"homepage" json:"homepage"`
	Description string   `mapstructure:"description" json:"description"`
}

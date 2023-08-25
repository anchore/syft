package pkg

// NpmPackageJSONMetadata holds parsing information for a javascript package.json file
type NpmPackageJSONMetadata struct {
	Name        string `mapstructure:"name" json:"name"`
	Version     string `mapstructure:"version" json:"version"`
	Author      string `mapstructure:"author" json:"author"`
	Homepage    string `mapstructure:"homepage" json:"homepage"`
	Description string `mapstructure:"description" json:"description"`
	URL         string `mapstructure:"url" json:"url"`
	Private     bool   `mapstructure:"private" json:"private"`
}

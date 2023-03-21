package pkg

// GemMetadata represents all metadata parsed from the gemspec file
type GemMetadata struct {
	Name     string   `mapstructure:"name" json:"name"`
	Version  string   `mapstructure:"version" json:"version"`
	Files    []string `mapstructure:"files" json:"files,omitempty"`
	Authors  []string `mapstructure:"authors" json:"authors,omitempty"`
	Homepage string   `mapstructure:"homepage" json:"homepage,omitempty"`
}

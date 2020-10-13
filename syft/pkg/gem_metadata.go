package pkg

type GemMetadata struct {
	Name     string   `mapstructure:"name" json:"name"`
	Version  string   `mapstructure:"version" json:"version"`
	Files    []string `mapstructure:"files" json:"files,omitempty"`
	Authors  []string `mapstructure:"authors" json:"authors,omitempty"`
	Licenses []string `mapstructure:"licenses" json:"licenses,omitempty"`
	Homepage string   `mapstructure:"homepage" json:"homepage,omitempty"`
}

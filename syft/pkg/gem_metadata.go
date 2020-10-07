package pkg

type GemMetadata struct {
	Name     string   `mapstructure:"name" json:"name"`
	Version  string   `mapstructure:"version" json:"version"`
	Files    []string `mapstructure:"files" json:"files"`
	Authors  []string `mapstructure:"authors" json:"authors"`
	Licenses []string `mapstructure:"licenses" json:"licenses"`
}

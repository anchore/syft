package pkg

type GemMetadata struct {
	Name    string `mapstructure:"name" json:"name"`
	Version string `mapstructure:"version" json:"version"`
	// TODO: add more fields from the gemspec
}

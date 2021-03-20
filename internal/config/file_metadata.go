package config

type FileMetadata struct {
	Cataloger catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	Digests   []string         `yaml:"digests" json:"digests" mapstructure:"digests"`
}

func (cfg *FileMetadata) build() error {
	return cfg.Cataloger.build()
}

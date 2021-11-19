package config

import (
	"github.com/anchore/syft/syft/source"
	"github.com/spf13/viper"
)

type FileMetadata struct {
	Cataloger catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	Digests   []string         `yaml:"digests" json:"digests" mapstructure:"digests"`
}

func (cfg FileMetadata) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("file-metadata.cataloger.enabled", catalogerEnabledDefault)
	v.SetDefault("file-metadata.cataloger.scope", source.SquashedScope)
	v.SetDefault("file-metadata.digests", []string{"sha256"})
}

func (cfg *FileMetadata) parseConfigValues() error {
	return cfg.Cataloger.parseConfigValues()
}

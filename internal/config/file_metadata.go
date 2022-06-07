package config

import (
	"github.com/spf13/viper"
)

type fileMetadata struct {
	Digests []string `yaml:"digests" json:"digests" mapstructure:"digests"`
}

func (cfg fileMetadata) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("file-metadata.digests", []string{"sha256"})
}

func (cfg *fileMetadata) parseConfigValues() error {
	return nil
}

package config

import (
	"github.com/spf13/viper"

	"github.com/anchore/syft/syft/source"
)

type fileClassification struct {
	Cataloger catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
}

func (cfg fileClassification) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("file-classification.cataloger.enabled", catalogerEnabledDefault)
	v.SetDefault("file-classification.cataloger.scope", source.SquashedScope)
}

func (cfg *fileClassification) parseConfigValues() error {
	return cfg.Cataloger.parseConfigValues()
}

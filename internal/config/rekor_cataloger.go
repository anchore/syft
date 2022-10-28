package config

import (
	"github.com/spf13/viper"

	"github.com/anchore/syft/syft/source"
)

var rekorCatalogerEnabledDefault = false

type rekorCataloger struct {
	Cataloger catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
}

func (cfg rekorCataloger) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("rekor-cataloger.cataloger.enabled", rekorCatalogerEnabledDefault)
	v.SetDefault("rekor-cataloger.cataloger.scope", source.SquashedScope)
}

func (cfg *rekorCataloger) parseConfigValues() error {
	return cfg.Cataloger.parseConfigValues()
}

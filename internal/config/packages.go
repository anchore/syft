package config

import "github.com/spf13/viper"

type Packages struct {
	Cataloger catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
}

func (cfg Packages) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("package.cataloger.enabled", true)
}

func (cfg *Packages) parseConfigValues() error {
	return cfg.Cataloger.parseConfigValues()
}

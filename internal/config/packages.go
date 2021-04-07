package config

import "github.com/spf13/viper"

type packages struct {
	Cataloger catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
}

func (cfg packages) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("package.cataloger.enabled", true)
}

func (cfg *packages) parseConfigValues() error {
	return cfg.Cataloger.parseConfigValues()
}

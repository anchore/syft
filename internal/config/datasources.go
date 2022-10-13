package config

import "github.com/spf13/viper"

type ExternalSources struct {
	Enabled bool `yaml:"external-sources-enabled" json:"external-sources-enabled" mapstructure:"external-sources-enabled"`
}

func (e ExternalSources) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("external-sources-enabled", false)
}

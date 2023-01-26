package config

import "github.com/spf13/viper"

type attest struct {
	Key      string `yaml:"key" json:"key" mapstructure:"key"`
	Password string `yaml:"password" json:"password" mapstructure:"password"`
}

func (cfg attest) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("attest.key", "")
	v.SetDefault("attest.password", "")
}

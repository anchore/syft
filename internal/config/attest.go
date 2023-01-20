package config

import "github.com/spf13/viper"

type attest struct {
	key string `yaml:"key" json:"key" mapstructure:"key"`
}

func (cfg attest) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("attest.key", "key.pub")
}

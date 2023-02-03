package config

import "github.com/spf13/viper"

type attest struct {
	// IMPORTANT: do not show the attestation key/password in any YAML/JSON output (sensitive information)
	Key      string `yaml:"-" json:"-" mapstructure:"key"`
	Password string `yaml:"-" json:"-" mapstructure:"password"`
}

func (cfg attest) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("attest.key", "")
	v.SetDefault("attest.password", "")
}

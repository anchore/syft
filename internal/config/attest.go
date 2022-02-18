package config

import (
	"github.com/spf13/viper"
	"os"
)

type attest struct {
	Key string `yaml:"key" json:"key" mapstructure:"key"`
	// IMPORTANT: do not show the password in any YAML/JSON output (sensitive information)
	Password string `yaml:"-" json:"-" mapstructure:"password"`
}

func (cfg *attest) parseConfigValues() error {
	if cfg.Password == "" {
		// we allow for configuration via syft config/env vars and additionally interop with known cosign config env vars
		if pw, ok := os.LookupEnv("COSIGN_PASSWORD"); ok {
			cfg.Password = pw
		}
	}

	return nil
}

func (cfg attest) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("attest.password", "")
}

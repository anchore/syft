package config

import (
	"fmt"
	"github.com/mitchellh/go-homedir"
	"os"

	"github.com/spf13/viper"
)

type attest struct {
	Key string `yaml:"key" json:"key" mapstructure:"key"` // same as --key, file path to the private key
	// IMPORTANT: do not show the password in any YAML/JSON output (sensitive information)
	Password string `yaml:"-" json:"-" mapstructure:"password"` // password for the private key
}

//nolint:unparam
func (cfg *attest) parseConfigValues() error {
	if cfg.Key != "" {
		expandedPath, err := homedir.Expand(cfg.Key)
		if err != nil {
			return fmt.Errorf("unable to expand key path=%q: %w", cfg.Key, err)
		}
		cfg.Key = expandedPath
	}

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

package config

import (
	"fmt"
	"os"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

type attest struct {
	KeyRef string `yaml:"key" json:"key" mapstructure:"key"` // same as --key, file path to the private key
	// IMPORTANT: do not show the password in any YAML/JSON output (sensitive information)
	Password string `yaml:"-" json:"-" mapstructure:"password"` // password for the private key
}

func (cfg *attest) parseConfigValues() error {
	if cfg.KeyRef != "" {
		expandedPath, err := homedir.Expand(cfg.KeyRef)
		if err != nil {
			return fmt.Errorf("unable to expand key path=%q: %w", cfg.KeyRef, err)
		}
		cfg.KeyRef = expandedPath
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

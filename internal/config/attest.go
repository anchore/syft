package config

import (
	"fmt"
	"os"

	"github.com/mitchellh/go-homedir"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/spf13/viper"
)

type attest struct {
	KeyRef string `yaml:"key" json:"key" mapstructure:"key"` // same as --key, file path to the private key
	// IMPORTANT: do not show the password in any YAML/JSON output (sensitive information)
	Password                 string `yaml:"-" json:"-" mapstructure:"password"` // password for the private key
	FulcioURL                string `yaml:"fulcio_url" json:"fulcioUrl" mapstructure:"fulcio_url"`
	InsecureSkipFulcioVerify bool   `yaml:""`
	RekorURL                 string `yaml:"rekor_url" json:"rekorUrl" mapstructure:"rekor_url"`
	OIDCIssuer               string `yaml:"oidc_issuer" json:"oidcIssuer" mapstructure:"oidc_issuer"`
	OIDCClientID             string `yaml:"oidc_client_id" json:"oidcClientId" mapstructure:"oidc_client_id"`
	OIDCClientSecret         string `yaml:"oidc_client_secret" json:"oidcClientSecret" mapstructure:"oidc_client_secret"`
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
	v.SetDefault("attest.fulcio_url", options.DefaultFulcioURL)
	v.SetDefault("attest.rekor_url", options.DefaultRekorURL)
	v.SetDefault("attest.oidc_issuer", options.DefaultOIDCIssuerURL)
	v.SetDefault("attest.oidc_client_id", "sigstore")
}

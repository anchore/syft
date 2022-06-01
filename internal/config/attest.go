package config

import (
	"fmt"
	"os"

	"github.com/mitchellh/go-homedir"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/spf13/viper"
)

// IMPORTANT: do not show the password in any YAML/JSON output (sensitive information)
type attest struct {
	KeyRef                   string `yaml:"key" json:"key" mapstructure:"key"` // same as --key, file path to the private key
	Cert                     string `yaml:"cert" json:"cert" mapstructure:"cert"`
	NoUpload                 bool   `yaml:"no_upload" json:"noUpload" mapstructure:"no_upload"`
	Force                    bool   `yaml:"force" json:"force" mapstructure:"force"`
	Recursive                bool   `yaml:"recursive" json:"recursive" mapstructure:"recursive"`
	Replace                  bool   `yaml:"replace" json:"replace" mapstructure:"replace"`
	Password                 string `yaml:"-" json:"-" mapstructure:"password"` // password for the private key
	FulcioURL                string `yaml:"fulcio_url" json:"fulcioUrl" mapstructure:"fulcio_url"`
	FulcioIdentityToken      string `yaml:"fulcio_identity_token" json:"fulcio_identity_token" mapstructure:"fulcio_identity_token"`
	InsecureSkipFulcioVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify" mapstructure:"insecure_skip_verify"`
	RekorURL                 string `yaml:"rekor_url" json:"rekorUrl" mapstructure:"rekor_url"`
	OIDCIssuer               string `yaml:"oidc_issuer" json:"oidcIssuer" mapstructure:"oidc_issuer"`
	OIDCClientID             string `yaml:"oidc_client_id" json:"oidcClientId" mapstructure:"oidc_client_id"`
	OIDCRedirectURL          string `yaml:"oidc_redirect_url" json:"OIDCRedirectURL" mapstructure:"oidc_redirect_url"`
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
	v.SetDefault("attest.key", "")
	v.SetDefault("attest.password", "")
	v.SetDefault("attest.fulcio_url", options.DefaultFulcioURL)
	v.SetDefault("attest.rekor_url", options.DefaultRekorURL)
	v.SetDefault("attest.oidc_issuer", options.DefaultOIDCIssuerURL)
	v.SetDefault("attest.oidc_client_id", "sigstore")
}

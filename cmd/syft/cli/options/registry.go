package options

import (
	"os"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope/pkg/image"
)

type RegistryCredentials struct {
	Authority string `yaml:"authority" json:"authority" mapstructure:"authority"`
	// IMPORTANT: do not show any credential information, use secret type to automatically redact the values
	Username secret `yaml:"username" json:"username" mapstructure:"username"`
	Password secret `yaml:"password" json:"password" mapstructure:"password"`
	Token    secret `yaml:"token" json:"token" mapstructure:"token"`
}

type registry struct {
	InsecureSkipTLSVerify bool                  `yaml:"insecure-skip-tls-verify" json:"insecure-skip-tls-verify" mapstructure:"insecure-skip-tls-verify"`
	InsecureUseHTTP       bool                  `yaml:"insecure-use-http" json:"insecure-use-http" mapstructure:"insecure-use-http"`
	Auth                  []RegistryCredentials `yaml:"auth" json:"auth" mapstructure:"auth"`
}

var _ clio.PostLoader = (*registry)(nil)

func (cfg *registry) PostLoad() error {
	// there may be additional credentials provided by env var that should be appended to the set of credentials
	authority, username, password, token :=
		os.Getenv("SYFT_REGISTRY_AUTH_AUTHORITY"),
		os.Getenv("SYFT_REGISTRY_AUTH_USERNAME"),
		os.Getenv("SYFT_REGISTRY_AUTH_PASSWORD"),
		os.Getenv("SYFT_REGISTRY_AUTH_TOKEN")

	if hasNonEmptyCredentials(username, password, token) {
		envCredentials := RegistryCredentials{
			Authority: authority,
			Username:  secret(username),
			Password:  secret(password),
			Token:     secret(token),
		}
		// note: we prepend the credentials such that the environment variables take precedence over on-disk configuration.
		// since this PostLoad is called before the PostLoad on the Auth credentials list,
		// all appropriate redactions will be added
		cfg.Auth = append([]RegistryCredentials{envCredentials}, cfg.Auth...)
	}
	return nil
}

func hasNonEmptyCredentials(username, password, token string) bool {
	return password != "" && username != "" || token != ""
}

func (cfg *registry) ToOptions() *image.RegistryOptions {
	var auth = make([]image.RegistryCredentials, len(cfg.Auth))
	for i, a := range cfg.Auth {
		auth[i] = image.RegistryCredentials{
			Authority: a.Authority,
			Username:  a.Username.String(),
			Password:  a.Password.String(),
			Token:     a.Token.String(),
		}
	}
	return &image.RegistryOptions{
		InsecureSkipTLSVerify: cfg.InsecureSkipTLSVerify,
		InsecureUseHTTP:       cfg.InsecureUseHTTP,
		Credentials:           auth,
	}
}

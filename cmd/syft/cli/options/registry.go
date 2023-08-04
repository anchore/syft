package options

import (
	"os"

	"github.com/anchore/fangs"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/redact"
)

type RegistryCredentials struct {
	Authority string `yaml:"authority" json:"authority" mapstructure:"authority"`
	Username  string `yaml:"username" json:"username" mapstructure:"username"`
	Password  string `yaml:"password" json:"password" mapstructure:"password"`
	Token     string `yaml:"token" json:"token" mapstructure:"token"`
}

var _ fangs.PostLoader = (*RegistryCredentials)(nil)

func (r *RegistryCredentials) PostLoad() error {
	// TODO ensure that the list of RegistryCredentials has PostLoad called
	// FIXME
	// IMPORTANT: do not show any credential information
	redact.Add(r.Username)
	redact.Add(r.Password)
	redact.Add(r.Token)
	return nil
}

type registry struct {
	InsecureSkipTLSVerify bool                  `yaml:"insecure-skip-tls-verify" json:"insecure-skip-tls-verify" mapstructure:"insecure-skip-tls-verify"`
	InsecureUseHTTP       bool                  `yaml:"insecure-use-http" json:"insecure-use-http" mapstructure:"insecure-use-http"`
	Auth                  []RegistryCredentials `yaml:"auth" json:"auth" mapstructure:"auth"`
}

func registryDefault() registry {
	return registry{}
}

var _ fangs.PostLoader = (*registry)(nil)

//nolint:unparam
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
			Username:  username,
			Password:  password,
			Token:     token,
		}
		if err := envCredentials.PostLoad(); err != nil {
			return err
		}
		// note: we prepend the credentials such that the environment variables take precedence over on-disk configuration.
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
			Username:  a.Username,
			Password:  a.Password,
			Token:     a.Token,
		}
	}
	return &image.RegistryOptions{
		InsecureSkipTLSVerify: cfg.InsecureSkipTLSVerify,
		InsecureUseHTTP:       cfg.InsecureUseHTTP,
		Credentials:           auth,
	}
}

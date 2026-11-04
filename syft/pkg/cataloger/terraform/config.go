package terraform

const (
	defaultRegistryHost    = "registry.terraform.io"
	defaultRegistryBaseURL = "https://" + defaultRegistryHost
)

type CatalogerConfig struct {
	// SearchRemoteLicenses enables downloading provider archives from the Terraform Registry to extract license information.
	// app-config: terraform.search-remote-licenses
	SearchRemoteLicenses bool `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	// RegistryBaseURL specifies the base URL of the Terraform Registry (or a mirror of it) used when searching for remote license information for providers sourced from registry.terraform.io. Providers from other registries are resolved via that registry's service discovery.
	// app-config: terraform.registry-base-url
	RegistryBaseURL string `yaml:"registry-base-url" json:"registry-base-url" mapstructure:"registry-base-url"`
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		SearchRemoteLicenses: false,
		RegistryBaseURL:      defaultRegistryBaseURL,
	}
}

func (c CatalogerConfig) WithSearchRemoteLicenses(input bool) CatalogerConfig {
	c.SearchRemoteLicenses = input
	return c
}

func (c CatalogerConfig) WithRegistryBaseURL(input string) CatalogerConfig {
	if input != "" {
		c.RegistryBaseURL = input
	}
	return c
}

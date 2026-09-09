package terraform

const defaultRegistryBaseURL = "https://registry.terraform.io"

type CatalogerConfig struct {
	// SearchRemoteLicenses enables downloading provider archives from the Terraform Registry to extract license information.
	// app-config: terraform.search-remote-licenses
	SearchRemoteLicenses bool `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	// RegistryBaseURL specifies the base URL for the Terraform Registry API used when searching for remote license information.
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

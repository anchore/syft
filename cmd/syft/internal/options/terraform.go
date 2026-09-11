package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/terraform"
)

type terraformConfig struct {
	SearchRemoteLicenses *bool  `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	RegistryBaseURL      string `json:"registry-base-url" yaml:"registry-base-url" mapstructure:"registry-base-url"`
}

var _ interface {
	clio.FieldDescriber
} = (*terraformConfig)(nil)

func defaultTerraformConfig() terraformConfig {
	def := terraform.DefaultCatalogerConfig()
	return terraformConfig{
		RegistryBaseURL: def.RegistryBaseURL,
	}
}

func (o *terraformConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.SearchRemoteLicenses, `enables Syft to use the network to download provider archives and extract license information`)
	descriptions.Add(&o.RegistryBaseURL, `base Terraform Registry URL to use`)
}

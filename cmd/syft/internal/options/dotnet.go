package options

import (
	"strings"

	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
)

type dotnetConfig struct {
	SearchLocalLicenses  bool   `yaml:"search-local-licenses" json:"search-local-licenses" mapstructure:"search-local-licenses"`
	SearchRemoteLicenses bool   `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Providers            string `yaml:"package-providers,omitempty" json:"package-providers,omitempty" mapstructure:"package-providers"`
}

func defaultDotnetConfig() dotnetConfig {
	def := dotnet.DefaultCatalogerConfig()
	return dotnetConfig{
		SearchLocalLicenses:  def.SearchLocalLicenses,
		SearchRemoteLicenses: def.SearchRemoteLicenses,
		Providers:            strings.Join(def.Providers, ","),
	}
}

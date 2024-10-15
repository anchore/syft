package options

import (
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
)

type dotnetConfig struct {
	SearchLocalLicenses  bool   `yaml:"search-local-licenses" json:"search-local-licenses" mapstructure:"search-local-licenses"`
	SearchRemoteLicenses bool   `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Providers            string `yaml:"package-providers,omitempty" json:"package-providers,omitempty" mapstructure:"package-providers"`
}

var _ interface {
	clio.FieldDescriber
} = (*dotnetConfig)(nil)

func (o *dotnetConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.SearchLocalLicenses, `search for NuGet package licences in the local cache of the system running Syft, note that this is outside the
container filesystem and probably outside the root of a local directory scan`)
	descriptions.Add(&o.SearchRemoteLicenses, `search for NuGet package licences by retrieving the package from a network proxy`)
	descriptions.Add(&o.Providers, `remote proxies (comma-separated) to use when retrieving NuGet packages from the network,
if unset this defaults to the NuGet-repositories known to the DotNet environment`)
}

func defaultDotnetConfig() dotnetConfig {
	def := dotnet.DefaultCatalogerConfig()
	return dotnetConfig{
		SearchLocalLicenses:  def.SearchLocalLicenses,
		SearchRemoteLicenses: def.SearchRemoteLicenses,
		Providers:            strings.Join(def.Providers, ","),
	}
}

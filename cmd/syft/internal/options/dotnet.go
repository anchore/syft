package options

import (
	"fmt"
	"os"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
)

type DotNetProviderCredentials []DotNetProviderCredential

func (dnpc DotNetProviderCredentials) String() string {
	result := ""

	partials := []string{}
	for _, credential := range dnpc {
		if credential.Valid() {
			partials = append(partials, fmt.Sprintf("%s:%s", credential.Username, credential.Password))
		}
	}

	if len(partials) > 0 {
		result = strings.Join(partials, ",")
	}

	return result
}

type DotNetProviderCredential struct {
	// IMPORTANT: do not show any credential information, use secret type to automatically redact the values
	Username secret `yaml:"username" json:"username" mapstructure:"username"`
	Password secret `yaml:"password" json:"password" mapstructure:"password"`
}

func (dnpc DotNetProviderCredential) Valid() bool {
	return dnpc.Username != "" && dnpc.Password != ""
}

type dotnetConfig struct {
	SearchLocalLicenses  *bool                     `yaml:"search-local-licenses" json:"search-local-licenses" mapstructure:"search-local-licenses"`
	LocalCachePaths      string                    `yaml:"local-cache-paths" json:"local-cache-paths" mapstructure:"local-cache-paths"`
	SearchRemoteLicenses *bool                     `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Providers            string                    `yaml:"package-providers,omitempty" json:"package-providers,omitempty" mapstructure:"package-providers"`
	ProviderCredentials  DotNetProviderCredentials `yaml:"package-provider-credentials,omitempty" json:"package-provider-credentials,omitempty" mapstructure:"package-provider-credentials"`
}

var _ interface {
	clio.PostLoader
	clio.FieldDescriber
} = (*dotnetConfig)(nil)

func retrieveCredentialByIndexExtension(index uint) (*DotNetProviderCredential, error) {
	username, password := "", ""
	if index == 0 {
		username, password =
			os.Getenv("SYFT_DOTNET_PACKAGE_PROVIDER_CREDENTIALS_USERNAME"),
			os.Getenv("SYFT_DOTNET_PACKAGE_PROVIDER_CREDENTIALS_PASSWORD")
	} else {
		username, password =
			os.Getenv(fmt.Sprintf("SYFT_DOTNET_PACKAGE_PROVIDER_CREDENTIALS_USERNAME_%d", index)),
			os.Getenv(fmt.Sprintf("SYFT_DOTNET_PACKAGE_PROVIDER_CREDENTIALS_PASSWORD_%d", index))
	}

	candidateCredential := &DotNetProviderCredential{
		Username: secret(username),
		Password: secret(password),
	}

	if candidateCredential.Valid() {
		return candidateCredential, nil
	}
	return nil, fmt.Errorf("credentials not found or invalid")
}

func (o *dotnetConfig) PostLoad() error {
	var err error

	index := uint(0)
	for err == nil {
		var credential *DotNetProviderCredential
		if credential, err = retrieveCredentialByIndexExtension(index); err == nil {
			o.ProviderCredentials = append(o.ProviderCredentials, *credential)
			index++
		}
	}
	return nil
}

func (o *dotnetConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.SearchLocalLicenses, `search for NuGet package licences in the local cache of the system running Syft, note that this is outside the
container filesystem and probably outside the root of a local directory scan`)
	descriptions.Add(&o.LocalCachePaths, `local cache folders (comma-separated) to use when retrieving NuGet packages locally, 
if unset this defaults to the NuGet cache folders known to the DotNet environment`)
	descriptions.Add(&o.SearchRemoteLicenses, `search for NuGet package licences by retrieving the package from a network proxy`)
	descriptions.Add(&o.Providers, `remote NuGet package providers (comma-separated) to use when retrieving NuGet packages from the network, 
if unset this defaults to the NuGet-repositories known to the DotNet environment`)
	descriptions.Add(&o.ProviderCredentials, `remote NuGet package provider credentials to use when retrieving NuGet packages from the network.`)
}

func defaultDotnetConfig() dotnetConfig {
	def := dotnet.DefaultCatalogerConfig()
	providerCredentials := []DotNetProviderCredential{}
	if len(def.ProviderCredentials) > 0 {
		for _, credential := range def.ProviderCredentials {
			providerCredentials = append(providerCredentials, DotNetProviderCredential{
				Username: secret(credential.Username),
				Password: secret(credential.Password),
			})
		}
	}
	return dotnetConfig{
		SearchLocalLicenses:  def.SearchLocalLicenses,
		LocalCachePaths:      strings.Join(def.LocalCachePaths, ","),
		SearchRemoteLicenses: def.SearchRemoteLicenses,
		Providers:            strings.Join(def.Providers, ","),
		ProviderCredentials:  providerCredentials,
	}
}

package options

import (
	"os"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
)

type dotNetProviderCredentials []dotNetProviderCredential

func (dnpc dotNetProviderCredentials) ToProviderCredentials() []dotnet.SimpleCredential {
	result := []dotnet.SimpleCredential{}
	for _, _credential := range dnpc {
		result = append(result, dotnet.SimpleCredential{
			Username: _credential.Username.String(),
			Password: _credential.Password.String(),
		})
	}

	return result
}

type dotNetProviderCredential struct {
	// IMPORTANT: do not show any credential information, use secret type to automatically redact the values
	Username secret `yaml:"username" json:"username" mapstructure:"username"`
	Password secret `yaml:"password" json:"password" mapstructure:"password"`
}

type dotnetConfig struct {
	DepPackagesMustHaveDLL bool `mapstructure:"dep-packages-must-have-dll" json:"dep-packages-must-have-dll" yaml:"dep-packages-must-have-dll"`

	DepPackagesMustClaimDLL bool `mapstructure:"dep-packages-must-claim-dll" json:"dep-packages-must-claim-dll" yaml:"dep-packages-must-claim-dll"`

	PropagateDLLClaimsToParents bool `mapstructure:"propagate-dll-claims-to-parents" json:"propagate-dll-claims-to-parents" yaml:"propagate-dll-claims-to-parents"`

	RelaxDLLClaimsWhenBundlingDetected bool `mapstructure:"relax-dll-claims-when-bundling-detected" json:"relax-dll-claims-when-bundling-detected" yaml:"relax-dll-claims-when-bundling-detected"`

	SearchLocalLicenses *bool `yaml:"search-local-licenses" json:"search-local-licenses" mapstructure:"search-local-licenses"`

	LocalCachePaths string `yaml:"local-cache-paths" json:"local-cache-paths" mapstructure:"local-cache-paths"`

	SearchRemoteLicenses *bool `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`

	NuGetRepositoryURLs string `yaml:"package-nugetrepositoryurls,omitempty" json:"package-nugetrepositoryurls,omitempty" mapstructure:"package-nugetrepositoryurls"`

	NuGetRepositoryCredentials dotNetProviderCredentials `yaml:"package-nugetrepository-credentials,omitempty" json:"package-nugetrepository-credentials,omitempty" mapstructure:"package-nugetrepository-credentials"`
}

var _ interface {
	clio.PostLoader
	clio.FieldDescriber
} = (*dotnetConfig)(nil)

func (o *dotnetConfig) PostLoad() error {
	username, password :=
		os.Getenv("SYFT_DOTNET_PACKAGE_PROVIDER_CREDENTIALS_USERNAME"),
		os.Getenv("SYFT_DOTNET_PACKAGE_PROVIDER_CREDENTIALS_PASSWORD")

	if username != "" && password != "" {
		o.NuGetRepositoryCredentials = append(o.NuGetRepositoryCredentials, dotNetProviderCredential{
			Username: secret(username),
			Password: secret(password),
		})
	}
	return nil
}

func (o *dotnetConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.DepPackagesMustHaveDLL, `only keep dep.json packages which an executable on disk is found. The package is also included if a DLL is found for any child package, even if the package itself does not have a DLL.`)
	descriptions.Add(&o.DepPackagesMustClaimDLL, `only keep dep.json packages which have a runtime/resource DLL claimed in the deps.json targets section (but not necessarily found on disk). The package is also included if any child package claims a DLL, even if the package itself does not claim a DLL.`)
	descriptions.Add(&o.PropagateDLLClaimsToParents, `treat DLL claims or on-disk evidence for child packages as DLL claims or on-disk evidence for any parent package`)
	descriptions.Add(&o.RelaxDLLClaimsWhenBundlingDetected, `show all packages from the deps.json if bundling tooling is present as a dependency (e.g. ILRepack)`)
	descriptions.Add(&o.SearchLocalLicenses, `search for NuGet package licences in the local cache of the system running Syft, note that this is outside the container filesystem and probably outside the root of a local directory scan`)
	descriptions.Add(&o.LocalCachePaths, `local cache folders (comma-separated) to use when retrieving NuGet packages locally; defaults to the standard NuGet cache folder`)
	descriptions.Add(&o.SearchRemoteLicenses, `search for NuGet package licences by retrieving the package from a network proxy`)
	descriptions.Add(&o.NuGetRepositoryURLs, `remote NuGet repository URLs (comma-separated) to use when retrieving NuGet packages from the network; defaults to the nuget.org-repository`)
	descriptions.Add(&o.NuGetRepositoryCredentials, `remote NuGet package provider credentials to use when retrieving NuGet packages from the network.`)
}

func defaultDotnetConfig() dotnetConfig {
	def := dotnet.DefaultCatalogerConfig()
	providerCredentials := []dotNetProviderCredential{}
	if len(def.NuGetRepositoryCredentials) > 0 {
		for _, credential := range def.NuGetRepositoryCredentials {
			providerCredentials = append(providerCredentials, dotNetProviderCredential{
				Username: secret(credential.Username),
				Password: secret(credential.Password),
			})
		}
	}
	return dotnetConfig{
		DepPackagesMustHaveDLL:             def.DepPackagesMustHaveDLL,
		DepPackagesMustClaimDLL:            def.DepPackagesMustClaimDLL,
		PropagateDLLClaimsToParents:        def.PropagateDLLClaimsToParents,
		RelaxDLLClaimsWhenBundlingDetected: def.RelaxDLLClaimsWhenBundlingDetected,
		SearchLocalLicenses:                &def.SearchLocalLicenses,
		LocalCachePaths:                    strings.Join(def.LocalCachePaths, ","),
		SearchRemoteLicenses:               &def.SearchRemoteLicenses,
		NuGetRepositoryURLs:                strings.Join(def.NuGetRepositoryURLs, ","),
		NuGetRepositoryCredentials:         providerCredentials,
	}
}

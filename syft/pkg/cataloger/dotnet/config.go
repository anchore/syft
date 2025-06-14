package dotnet

import (
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/anchore/syft/syft/credential"
)

const (
	defaultNuGetProvider = "https://api.nuget.org/v3-flatcontainer/"
)

type CatalogerConfig struct {
	// DepPackagesMustHaveDLL allows for deps.json packages to be included only if there is a DLL on disk for that package.
	DepPackagesMustHaveDLL bool `mapstructure:"dep-packages-must-have-dll" json:"dep-packages-must-have-dll" yaml:"dep-packages-must-have-dll"`

	// DepPackagesMustClaimDLL allows for deps.json packages to be included only if there is a runtime/resource DLL claimed in the deps.json targets section.
	// This does not require such claimed DLLs to exist on disk. The behavior of this
	DepPackagesMustClaimDLL bool `mapstructure:"dep-packages-must-claim-dll" json:"dep-packages-must-claim-dll" yaml:"dep-packages-must-claim-dll"`

	// PropagateDLLClaimsToParents allows for deps.json packages to be included if any child (transitive) package claims a DLL. This applies to both the claims configuration and evidence-on-disk configurations.
	PropagateDLLClaimsToParents bool `mapstructure:"propagate-dll-claims-to-parents" json:"propagate-dll-claims-to-parents" yaml:"propagate-dll-claims-to-parents"`

	// RelaxDLLClaimsWhenBundlingDetected will look for indications of IL bundle tooling via deps.json package names
	// and, if found (and this config option is enabled), will relax the DepPackagesMustClaimDLL value to `false` only in those cases.
	RelaxDLLClaimsWhenBundlingDetected bool `mapstructure:"relax-dll-claims-when-bundling-detected" json:"relax-dll-claims-when-bundling-detected" yaml:"relax-dll-claims-when-bundling-detected"`

	SearchLocalLicenses bool     `mapstructure:"search-local-licenses" json:"search-local-licenses" yaml:"search-local-licenses"`
	LocalCachePaths     []string `mapstructure:"local-cache-paths" json:"local-cache-paths" yaml:"local-cache-paths"`

	SearchRemoteLicenses bool                          `mapstructure:"search-remote-licenses" json:"search-remote-licenses" yaml:"search-remote-licenses"`
	Providers            []string                      `mapstructure:"package-providers" json:"package-providers,omitempty" yaml:"package-providers,omitempty"`
	ProviderCredentials  []credential.SimpleCredential `mapstructure:"package-provider-credentials" json:"package-provider-credentials,omitempty" yaml:"package-provider-credentials,omitempty"`
}

func (c CatalogerConfig) WithDepPackagesMustHaveDLL(requireDlls bool) CatalogerConfig {
	c.DepPackagesMustHaveDLL = requireDlls
	return c
}

func (c CatalogerConfig) WithDepPackagesMustClaimDLL(requireDlls bool) CatalogerConfig {
	c.DepPackagesMustClaimDLL = requireDlls
	return c
}

func (c CatalogerConfig) WithRelaxDLLClaimsWhenBundlingDetected(relax bool) CatalogerConfig {
	c.RelaxDLLClaimsWhenBundlingDetected = relax
	return c
}

func (c CatalogerConfig) WithPropagateDLLClaimsToParents(propagate bool) CatalogerConfig {
	c.PropagateDLLClaimsToParents = propagate
	return c
}

func (c CatalogerConfig) WithSearchLocalLicenses(input bool) CatalogerConfig {
	c.SearchLocalLicenses = input
	if c.SearchLocalLicenses && len(c.LocalCachePaths) == 0 {
		c.WithLocalCachePaths(getDefaultLocalNuGetCachePath())
	}
	return c
}

func (c CatalogerConfig) WithLocalCachePaths(input string) CatalogerConfig {
	if input == "" {
		return c
	}
	c.LocalCachePaths = strings.Split(input, ",")
	return c
}

func (c CatalogerConfig) WithSearchRemoteLicenses(input bool) CatalogerConfig {
	c.SearchRemoteLicenses = input
	if c.SearchRemoteLicenses && len(c.Providers) == 0 {
		c.WithProviders(defaultNuGetProvider)
	}
	return c
}

func (c CatalogerConfig) WithProviders(input string) CatalogerConfig {
	if input == "" {
		return c
	}
	c.Providers = strings.Split(input, ",")
	return c
}

func (c CatalogerConfig) WithCredentials(input []credential.SimpleCredential) CatalogerConfig {
	if len(input) == 0 {
		return c
	}

	c.ProviderCredentials = []credential.SimpleCredential{}

	for _, _credential := range input {
		if _credential.Valid() {
			c.ProviderCredentials = append(c.ProviderCredentials, _credential)
		}
	}

	return c
}

func getDefaultLocalNuGetCachePath() string {
	if runtime.GOOS == "windows" {
		return path.Clean(path.Join(os.Getenv("USERPROFILE"), ".nuget", "packages"))
	}
	return "~/.nuget/packages"
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		DepPackagesMustHaveDLL:             false,
		DepPackagesMustClaimDLL:            true,
		PropagateDLLClaimsToParents:        true,
		RelaxDLLClaimsWhenBundlingDetected: true,
		SearchLocalLicenses:                true,
		LocalCachePaths:                    []string{getDefaultLocalNuGetCachePath()},
		SearchRemoteLicenses:               false,
		Providers:                          []string{defaultNuGetProvider},
		ProviderCredentials:                []credential.SimpleCredential{},
	}
}

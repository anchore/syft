package dotnet

import (
	"strings"

	"github.com/anchore/syft/syft/credential"
)

const (
	defaultNuGetProvider = "https://api.nuget.org/v3-flatcontainer/"
)

type CatalogerConfig struct {
	// DepPackagesMustHaveDLL allows for deps.json packages to be included only if there is a DLL on disk for that package.
	// app-config: dotnet.dep-packages-must-have-dll
	DepPackagesMustHaveDLL bool `mapstructure:"dep-packages-must-have-dll" json:"dep-packages-must-have-dll" yaml:"dep-packages-must-have-dll"`

	// DepPackagesMustClaimDLL allows for deps.json packages to be included only if there is a runtime/resource DLL claimed in the deps.json targets section.
	// This does not require such claimed DLLs to exist on disk. The behavior of this
	// app-config: dotnet.dep-packages-must-claim-dll
	DepPackagesMustClaimDLL bool `mapstructure:"dep-packages-must-claim-dll" json:"dep-packages-must-claim-dll" yaml:"dep-packages-must-claim-dll"`

	// PropagateDLLClaimsToParents allows for deps.json packages to be included if any child (transitive) package claims a DLL. This applies to both the claims configuration and evidence-on-disk configurations.
	// app-config: dotnet.propagate-dll-claims-to-parents
	PropagateDLLClaimsToParents bool `mapstructure:"propagate-dll-claims-to-parents" json:"propagate-dll-claims-to-parents" yaml:"propagate-dll-claims-to-parents"`

	// RelaxDLLClaimsWhenBundlingDetected will look for indications of IL bundle tooling via deps.json package names
	// and, if found (and this config option is enabled), will relax the DepPackagesMustClaimDLL value to `false` only in those cases.
	// app-config: dotnet.relax-dll-claims-when-bundling-detected
	RelaxDLLClaimsWhenBundlingDetected bool `mapstructure:"relax-dll-claims-when-bundling-detected" json:"relax-dll-claims-when-bundling-detected" yaml:"relax-dll-claims-when-bundling-detected"`

	SearchLocalLicenses bool     `mapstructure:"search-local-licenses" json:"search-local-licenses" yaml:"search-local-licenses"`
	LocalCachePaths     []string `mapstructure:"local-cache-paths" json:"local-cache-paths" yaml:"local-cache-paths"`

	SearchRemoteLicenses       bool                          `mapstructure:"search-remote-licenses" json:"search-remote-licenses" yaml:"search-remote-licenses"`
	NuGetRepositoryURLs        []string                      `mapstructure:"package-nugetrepositoryurls" json:"package-nugetrepositoryurls,omitempty" yaml:"package-nugetrepositoryurls,omitempty"`
	NuGetRepositoryCredentials []credential.SimpleCredential `mapstructure:"package-nugetrepository-credentials" json:"package-nugetrepository-credentials,omitempty" yaml:"package-nugetrepository-credentials,omitempty"`
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
	if c.SearchRemoteLicenses && len(c.NuGetRepositoryURLs) == 0 {
		c.WithNuGetRepositoryURLs(defaultNuGetProvider)
	}
	return c
}

func (c CatalogerConfig) WithNuGetRepositoryURLs(input string) CatalogerConfig {
	if input == "" {
		return c
	}
	c.NuGetRepositoryURLs = strings.Split(input, ",")
	return c
}

func (c CatalogerConfig) WithCredentials(input []credential.SimpleCredential) CatalogerConfig {
	if len(input) == 0 {
		return c
	}

	c.NuGetRepositoryCredentials = []credential.SimpleCredential{}

	for _, credential := range input {
		if credential.Valid() {
			c.NuGetRepositoryCredentials = append(c.NuGetRepositoryCredentials, credential)
		}
	}

	return c
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		DepPackagesMustHaveDLL:             false,
		DepPackagesMustClaimDLL:            true,
		PropagateDLLClaimsToParents:        true,
		RelaxDLLClaimsWhenBundlingDetected: true,
		SearchLocalLicenses:                true,
		LocalCachePaths:                    []string{},
		SearchRemoteLicenses:               false,
		NuGetRepositoryURLs:                []string{defaultNuGetProvider},
		NuGetRepositoryCredentials:         []credential.SimpleCredential{},
	}
}

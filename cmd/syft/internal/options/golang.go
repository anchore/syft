package options

import (
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
)

type golangConfig struct {
	SearchLocalModCacheLicenses *bool                         `json:"search-local-mod-cache-licenses" yaml:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`
	LocalModCacheDir            string                        `json:"local-mod-cache-dir" yaml:"local-mod-cache-dir" mapstructure:"local-mod-cache-dir"`
	SearchRemoteLicenses        *bool                         `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Proxy                       string                        `json:"proxy" yaml:"proxy" mapstructure:"proxy"`
	NoProxy                     string                        `json:"no-proxy" yaml:"no-proxy" mapstructure:"no-proxy"`
	MainModuleVersion           golangMainModuleVersionConfig `json:"main-module-version" yaml:"main-module-version" mapstructure:"main-module-version"`
}

var _ interface {
	clio.FieldDescriber
} = (*golangConfig)(nil)

func (o *golangConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.SearchLocalModCacheLicenses, `search for go package licences in the GOPATH of the system running Syft, note that this is outside the
container filesystem and potentially outside the root of a local directory scan`)
	descriptions.Add(&o.LocalModCacheDir, `specify an explicit go mod cache directory, if unset this defaults to $GOPATH/pkg/mod or $HOME/go/pkg/mod`)
	descriptions.Add(&o.SearchRemoteLicenses, `search for go package licences by retrieving the package from a network proxy`)
	descriptions.Add(&o.Proxy, `remote proxy to use when retrieving go packages from the network,
if unset this defaults to $GOPROXY followed by https://proxy.golang.org`)
	descriptions.Add(&o.NoProxy, `specifies packages which should not be fetched by proxy
if unset this defaults to $GONOPROXY`)
	descriptions.Add(&o.MainModuleVersion, `the go main module version discovered from binaries built with the go compiler will
always show (devel) as the version. Use these options to control heuristics to guess
a more accurate version from the binary.`)
	descriptions.Add(&o.MainModuleVersion.FromLDFlags, `look for LD flags that appear to be setting a version (e.g. -X main.version=1.0.0)`)
	descriptions.Add(&o.MainModuleVersion.FromBuildSettings, `use the build settings (e.g. vcs.version & vcs.time) to craft a v0 pseudo version 
(e.g. v0.0.0-20220308212642-53e6d0aaf6fb) when a more accurate version cannot be found otherwise`)
	descriptions.Add(&o.MainModuleVersion.FromContents, `search for semver-like strings in the binary contents`)
}

type golangMainModuleVersionConfig struct {
	FromLDFlags       bool `json:"from-ld-flags" yaml:"from-ld-flags" mapstructure:"from-ld-flags"`
	FromContents      bool `json:"from-contents" yaml:"from-contents" mapstructure:"from-contents"`
	FromBuildSettings bool `json:"from-build-settings" yaml:"from-build-settings" mapstructure:"from-build-settings"`
}

func defaultGolangConfig() golangConfig {
	def := golang.DefaultCatalogerConfig()
	return golangConfig{
		SearchLocalModCacheLicenses: nil, // this defaults to false, which is the API default
		LocalModCacheDir:            def.LocalModCacheDir,
		SearchRemoteLicenses:        nil, // this defaults to false, which is the API default
		Proxy:                       strings.Join(def.Proxies, ","),
		NoProxy:                     strings.Join(def.NoProxy, ","),
		MainModuleVersion: golangMainModuleVersionConfig{
			FromLDFlags:       def.MainModuleVersion.FromLDFlags,
			FromContents:      def.MainModuleVersion.FromContents,
			FromBuildSettings: def.MainModuleVersion.FromBuildSettings,
		},
	}
}

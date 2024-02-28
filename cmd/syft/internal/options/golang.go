package options

import (
	"strings"

	"github.com/anchore/syft/syft/pkg/cataloger/golang"
)

type golangConfig struct {
	SearchLocalModCacheLicenses bool                          `json:"search-local-mod-cache-licenses" yaml:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`
	LocalModCacheDir            string                        `json:"local-mod-cache-dir" yaml:"local-mod-cache-dir" mapstructure:"local-mod-cache-dir"`
	SearchRemoteLicenses        bool                          `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Proxy                       string                        `json:"proxy" yaml:"proxy" mapstructure:"proxy"`
	NoProxy                     string                        `json:"no-proxy" yaml:"no-proxy" mapstructure:"no-proxy"`
	MainModuleVersion           golangMainModuleVersionConfig `json:"main-module-version" yaml:"main-module-version" mapstructure:"main-module-version"`
}

type golangMainModuleVersionConfig struct {
	FromLDFlags       bool `json:"from-ld-flags" yaml:"from-ld-flags" mapstructure:"from-ld-flags"`
	FromContents      bool `json:"from-contents" yaml:"from-contents" mapstructure:"from-contents"`
	FromBuildSettings bool `json:"from-build-settings" yaml:"from-build-settings" mapstructure:"from-build-settings"`
}

func defaultGolangConfig() golangConfig {
	def := golang.DefaultCatalogerConfig()
	return golangConfig{
		SearchLocalModCacheLicenses: def.SearchLocalModCacheLicenses,
		LocalModCacheDir:            def.LocalModCacheDir,
		SearchRemoteLicenses:        def.SearchRemoteLicenses,
		Proxy:                       strings.Join(def.Proxies, ","),
		NoProxy:                     strings.Join(def.NoProxy, ","),
		MainModuleVersion: golangMainModuleVersionConfig{
			FromLDFlags:       def.MainModuleVersion.FromLDFlags,
			FromContents:      def.MainModuleVersion.FromContents,
			FromBuildSettings: def.MainModuleVersion.FromBuildSettings,
		},
	}
}

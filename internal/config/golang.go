package config

import "github.com/spf13/viper"

type golang struct {
	SearchLocalModCacheLicenses bool   `json:"search-local-mod-cache-licenses" yaml:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`
	LocalModCacheDir            string `json:"local-mod-cache-dir" yaml:"local-mod-cache-dir" mapstructure:"local-mod-cache-dir"`
	SearchInternetLicenses      bool   `json:"search-internet-licenses" yaml:"search-internet-licenses" mapstructure:"search-internet-licenses"`
	RemoteProxy                 string `json:"remote-proxy" yaml:"remote-proxy" mapstructure:"remote-proxy"`
}

func (cfg golang) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("golang.search-local-mod-cache-licenses", false)
	v.SetDefault("golang.search-internet-licenses", false)
	v.SetDefault("golang.local-mod-cache-dir", "")
	v.SetDefault("golang.remote-proxy", "https://proxy.golang.org")
}

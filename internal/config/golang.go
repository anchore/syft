package config

import "github.com/spf13/viper"

type golang struct {
	SearchLocalModCacheLicenses bool   `json:"search-local-mod-cache-licenses" yaml:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`
	SearchRemoteLicenses        bool   `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	LocalModCacheDir            string `json:"local-mod-cache-dir" yaml:"local-mod-cache-dir" mapstructure:"local-mod-cache-dir"`
}

func (cfg golang) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("golang.search-local-mod-cache-licenses", false)
	v.SetDefault("golang.search-remote-licenses", false)
	v.SetDefault("golang.local-mod-cache-dir", "")
}

package config

import "github.com/spf13/viper"

type golang struct {
	SearchLocalGoModLicenses bool `json:"search-local-mod-cache-licenses" yaml:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`
}

func (cfg golang) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("golang.search-local-mod-cache-licenses", false)
}

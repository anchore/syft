package config

import "github.com/spf13/viper"

type golang struct {
	SearchLocalGoModLicenses bool `json:"search-local-go-mod-licenses" yaml:"search-local-go-mod-licenses" mapstructure:"search-local-go-mod-licenses"`
}

func (cfg golang) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("package.cataloger.golang.search-local-go-mod-licenses", false)
}

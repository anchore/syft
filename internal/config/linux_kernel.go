package config

import "github.com/spf13/viper"

type linuxKernel struct {
	CatalogModules bool `json:"catalog-modules" yaml:"catalog-modules" mapstructure:"catalog-modules"`
}

func (cfg linuxKernel) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("linux-kernel.catalog-modules", true)
}

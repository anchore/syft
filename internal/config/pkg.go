package config

import (
	"github.com/anchore/syft/syft/cataloger/packages"
	"github.com/spf13/viper"
)

type pkg struct {
	SearchUnindexedArchives bool `yaml:"search-unindexed-archives" json:"search-unindexed-archives" mapstructure:"search-unindexed-archives"`
	SearchIndexedArchives   bool `yaml:"search-indexed-archives" json:"search-indexed-archives" mapstructure:"search-indexed-archives"`
}

func (cfg pkg) loadDefaultValues(v *viper.Viper) {
	c := packages.DefaultSearchConfig()
	v.SetDefault("package.search-unindexed-archives", c.IncludeUnindexedArchives)
	v.SetDefault("package.search-indexed-archives", c.IncludeIndexedArchives)
}

func (cfg pkg) ToConfig() packages.SearchConfig {
	return packages.SearchConfig{
		IncludeIndexedArchives:   cfg.SearchIndexedArchives,
		IncludeUnindexedArchives: cfg.SearchUnindexedArchives,
	}
}

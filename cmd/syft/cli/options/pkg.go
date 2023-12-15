package options

import "github.com/anchore/syft/syft/cataloging"

type packageConfig struct {
	SearchUnindexedArchives         bool `yaml:"search-unindexed-archives" json:"search-unindexed-archives" mapstructure:"search-unindexed-archives"`
	SearchIndexedArchives           bool `yaml:"search-indexed-archives" json:"search-indexed-archives" mapstructure:"search-indexed-archives"`
}

func defaultPkg() packageConfig {
	c := cataloging.DefaultArchiveSearchConfig()
	return packageConfig{
		SearchIndexedArchives:           c.IncludeIndexedArchives,
		SearchUnindexedArchives:         c.IncludeUnindexedArchives,
	}
}

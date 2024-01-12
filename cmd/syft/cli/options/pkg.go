package options

import "github.com/anchore/syft/syft/cataloging"

type packageConfig struct {
	SearchUnindexedArchives         bool `yaml:"search-unindexed-archives" json:"search-unindexed-archives" mapstructure:"search-unindexed-archives"`
	SearchIndexedArchives           bool `yaml:"search-indexed-archives" json:"search-indexed-archives" mapstructure:"search-indexed-archives"`
	ExcludeBinaryOverlapByOwnership bool `yaml:"exclude-binary-overlap-by-ownership" json:"exclude-binary-overlap-by-ownership" mapstructure:"exclude-binary-overlap-by-ownership"` // exclude synthetic binary packages owned by os package files
}

func defaultPackageConfig() packageConfig {
	c := cataloging.DefaultArchiveSearchConfig()
	return packageConfig{
		SearchIndexedArchives:           c.IncludeIndexedArchives,
		SearchUnindexedArchives:         c.IncludeUnindexedArchives,
		ExcludeBinaryOverlapByOwnership: true,
	}
}

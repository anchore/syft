package options

import (
	"github.com/anchore/syft/syft/pkg/cataloger"
)

type pkg struct {
	Cataloger               scope `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	SearchUnindexedArchives bool  `yaml:"search-unindexed-archives" json:"search-unindexed-archives" mapstructure:"search-unindexed-archives"`
	SearchIndexedArchives   bool  `yaml:"search-indexed-archives" json:"search-indexed-archives" mapstructure:"search-indexed-archives"`
}

func defaultPkg() pkg {
	c := cataloger.DefaultSearchConfig()
	return pkg{
		SearchIndexedArchives:   c.IncludeIndexedArchives,
		SearchUnindexedArchives: c.IncludeUnindexedArchives,
		Cataloger: scope{
			Enabled: true,
			Scope:   c.Scope.String(),
		},
	}
}

package options

import (
	"github.com/anchore/syft/syft/pkg/cataloger"
)

type pkg struct {
	Cataloger               catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	SearchUnindexedArchives bool             `yaml:"search-unindexed-archives" json:"search-unindexed-archives" mapstructure:"search-unindexed-archives"`
	SearchIndexedArchives   bool             `yaml:"search-indexed-archives" json:"search-indexed-archives" mapstructure:"search-indexed-archives"`
}

func pkgDefault() pkg {
	c := cataloger.DefaultSearchConfig()
	return pkg{
		SearchIndexedArchives:   c.IncludeIndexedArchives,
		SearchUnindexedArchives: c.IncludeUnindexedArchives,
		Cataloger: catalogerOptions{
			Enabled: true,
			Scope:   c.Scope,
		},
	}
}

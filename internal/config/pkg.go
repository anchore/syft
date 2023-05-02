package config

import (
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
)

type pkgOptions struct {
	Cataloger               catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	SearchUnindexedArchives bool             `yaml:"search-unindexed-archives" json:"search-unindexed-archives" mapstructure:"search-unindexed-archives"`
	SearchIndexedArchives   bool             `yaml:"search-indexed-archives" json:"search-indexed-archives" mapstructure:"search-indexed-archives"`
}

func newPkgOptions(enabled bool) pkgOptions {
	c := cataloger.DefaultSearchConfig()
	return pkgOptions{
		Cataloger:               newCatalogerOptions(enabled, source.SquashedScope),
		SearchIndexedArchives:   c.IncludeIndexedArchives,
		SearchUnindexedArchives: c.IncludeUnindexedArchives,
	}
}

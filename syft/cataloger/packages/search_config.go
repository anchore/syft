package packages

import (
	"github.com/anchore/syft/syft/cataloger/packages/java"
)

type SearchConfig struct {
	IncludeIndexedArchives   bool
	IncludeUnindexedArchives bool
}

func DefaultSearchConfig() SearchConfig {
	return SearchConfig{
		IncludeIndexedArchives:   true,
		IncludeUnindexedArchives: false,
	}
}

func (c SearchConfig) Java() java.CatalogerConfig {
	return java.CatalogerConfig{
		SearchUnindexedArchives: c.IncludeUnindexedArchives,
		SearchIndexedArchives:   c.IncludeIndexedArchives,
	}
}

package cataloger

import (
	"github.com/anchore/syft/syft/source"
)

type SearchConfig struct {
	IncludeIndexedArchives   bool
	IncludeUnindexedArchives bool
	Scope                    source.Scope
}

func DefaultSearchConfig() SearchConfig {
	return SearchConfig{
		IncludeIndexedArchives:   true,
		IncludeUnindexedArchives: false,
		Scope:                    source.SquashedScope,
	}
}

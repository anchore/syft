package packages

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

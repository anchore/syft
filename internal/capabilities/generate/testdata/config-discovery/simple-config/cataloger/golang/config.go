package golang

// CatalogerConfig contains configuration for the golang cataloger
type CatalogerConfig struct {
	// enable searching for go package licenses in the local mod cache
	// app-config: golang.search-local-mod-cache-licenses
	SearchLocalModCacheLicenses bool

	// base URL for npm registry
	// app-config: golang.npm-base-url
	NpmBaseURL string

	// list of globs to search for go.mod files
	// app-config: golang.search-patterns
	SearchPatterns []string
}

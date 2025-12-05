package golang

// MainModuleVersionConfig contains nested configuration for main module version detection
type MainModuleVersionConfig struct {
	// extract version from LD flags
	// app-config: golang.main-module-version.from-ld-flags
	FromLDFlags bool

	// extract version from build info
	// app-config: golang.main-module-version.from-build-info
	FromBuildInfo bool
}

// CatalogerConfig contains configuration for the golang cataloger
type CatalogerConfig struct {
	// enable searching for go package licenses in the local mod cache
	// app-config: golang.search-local-mod-cache-licenses
	SearchLocalModCacheLicenses bool

	// main module version configuration
	MainModuleVersion MainModuleVersionConfig
}

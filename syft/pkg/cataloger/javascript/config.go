package javascript

const npmBaseURL = "https://registry.npmjs.org"

type CatalogerConfig struct {
	// SearchRemoteLicenses enables querying the NPM registry API to retrieve license information for packages that are missing license data in their local metadata.
	// app-config: javascript.search-remote-licenses
	SearchRemoteLicenses bool `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	// NPMBaseURL specifies the base URL for the NPM registry API used when searching for remote license information.
	// app-config: javascript.npm-base-url
	NPMBaseURL string `json:"npm-base-url" yaml:"npm-base-url" mapstructure:"npm-base-url"`
	// IncludeDevDependencies controls whether development dependencies should be included in the catalog results, in addition to production dependencies.
	// app-config: javascript.include-dev-dependencies
	IncludeDevDependencies bool `json:"include-dev-dependencies" yaml:"include-dev-dependencies" mapstructure:"include-dev-dependencies"`
	// PnpmExcludeDevDependencies controls whether development dependencies should be excluded from PNPM lockfiles.
	// app-config: javascript.pnpm-exclude-dev-dependencies
	PnpmExcludeDevDependencies bool `json:"pnpm-exclude-dev-dependencies" yaml:"pnpm-exclude-dev-dependencies" mapstructure:"pnpm-exclude-dev-dependencies"`
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		SearchRemoteLicenses: false,
		NPMBaseURL:           npmBaseURL,
	}
}

func (j CatalogerConfig) WithSearchRemoteLicenses(input bool) CatalogerConfig {
	j.SearchRemoteLicenses = input
	return j
}

func (j CatalogerConfig) WithNpmBaseURL(input string) CatalogerConfig {
	if input != "" {
		j.NPMBaseURL = input
	}
	return j
}

func (j CatalogerConfig) WithIncludeDevDependencies(input bool) CatalogerConfig {
	j.IncludeDevDependencies = input
	return j
}

func (j CatalogerConfig) WithPnpmExcludeDevDependencies(input bool) CatalogerConfig {
	j.PnpmExcludeDevDependencies = input
	return j
}

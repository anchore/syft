package javascript

const npmBaseURL = "https://registry.npmjs.org"

type CatalogerConfig struct {
	SearchRemoteLicenses   bool   `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	NPMBaseURL             string `json:"npm-base-url" yaml:"npm-base-url" mapstructure:"npm-base-url"`
	IncludeDevDependencies bool   `json:"include-dev-dependencies" yaml:"include-dev-dependencies" mapstructure:"include-dev-dependencies"`
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

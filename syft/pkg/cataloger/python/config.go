package python

const pypiBaseURL = "https://pypi.org/pypi"

type CatalogerConfig struct {
	// GuessUnpinnedRequirements attempts to infer package versions from version constraints when no explicit version is specified in requirements files.
	// app-config: python.guess-unpinned-requirements
	GuessUnpinnedRequirements bool `yaml:"guess-unpinned-requirements" json:"guess-unpinned-requirements" mapstructure:"guess-unpinned-requirements"`
	// SearchRemoteLicenses enables querying the PyPI registry API to retrieve license information for packages that are missing license data in their local metadata.
	// app-config: python.search-remote-licenses
	SearchRemoteLicenses bool `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	// PypiBaseURL specifies the base URL for the Pypi registry API used when searching for remote license information.
	// app-config: python.pypi-base-url
	PypiBaseURL string `json:"pypi-base-url" yaml:"pypi-base-url" mapstructure:"pypi-base-url"`
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		GuessUnpinnedRequirements: false,
		SearchRemoteLicenses:      false,
		PypiBaseURL:               pypiBaseURL,
	}
}

func (c CatalogerConfig) WithSearchRemoteLicenses(input bool) CatalogerConfig {
	c.SearchRemoteLicenses = input
	return c
}

func (c CatalogerConfig) WithGuessUnpinnedRequirements(input bool) CatalogerConfig {
	c.GuessUnpinnedRequirements = input
	return c
}

func (c CatalogerConfig) WithPypiBaseURL(input string) CatalogerConfig {
	if input != "" {
		c.PypiBaseURL = input
	}
	return c
}

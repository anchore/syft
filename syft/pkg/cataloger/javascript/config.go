package javascript

const npmBaseURL = "https://registry.npmjs.org"

type CatalogerConfig struct {
	searchRemoteLicenses bool
	npmBaseURL           string
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		searchRemoteLicenses: false,
		npmBaseURL:           npmBaseURL,
	}
}

func (j CatalogerConfig) WithSearchRemoteLicenses(input bool) CatalogerConfig {
	j.searchRemoteLicenses = input
	return j
}

func (j CatalogerConfig) WithNpmBaseURL(input string) CatalogerConfig {
	if input != "" {
		j.npmBaseURL = input
	}
	return j
}

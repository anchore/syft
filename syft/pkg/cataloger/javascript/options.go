package javascript

type CatalogerConfig struct {
	searchRemoteLicenses bool
	npmBaseURL           string
}

func (g CatalogerConfig) WithSearchRemoteLicenses(input bool) CatalogerConfig {
	g.searchRemoteLicenses = input
	return g
}

// NewCatalogerOpts create a NewCatalogerOpts with default options, which includes:
// - searchRemoteLicenses is false
func NewCatalogerOpts() CatalogerConfig {
	g := CatalogerConfig{}

	return g
}

func (g CatalogerConfig) WithNpmBaseURL(input string) CatalogerConfig {
	g.npmBaseURL = input
	return g
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		searchRemoteLicenses: false,
		npmBaseURL:           "https://registry.npmjs.org",
	}
}

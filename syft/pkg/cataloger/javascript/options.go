package javascript

type CatalogerConfig struct {
	searchRemoteLicenses bool
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

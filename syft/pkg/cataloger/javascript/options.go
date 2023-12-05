package javascript

type YarnLockCatalogerConfig struct {
	searchRemoteLicenses bool
}

func (g YarnLockCatalogerConfig) WithSearchRemoteLicenses(input bool) YarnLockCatalogerConfig {
	g.searchRemoteLicenses = input
	return g
}

// NewCatalogerOpts create a NewCatalogerOpts with default options, which includes:
// - searchRemoteLicenses is false
func NewCatalogerOpts() YarnLockCatalogerConfig {
	g := YarnLockCatalogerConfig{}

	return g
}

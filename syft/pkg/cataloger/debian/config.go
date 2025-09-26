package debian

type CatalogerConfig struct {
	IncludeDeInstalled bool `yaml:"include-deinstalled" json:"include-deinstalled" mapstructure:"include-deinstalled"`
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		IncludeDeInstalled: false,
	}
}

func (c CatalogerConfig) WithIncludeDeInstalled(include bool) CatalogerConfig {
	c.IncludeDeInstalled = include
	return c
}
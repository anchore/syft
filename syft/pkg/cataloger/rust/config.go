package rust

type CatalogerConfig struct {
	// IncludeDevDependencies includes dependencies used only for tests, examples, and benchmarks.
	// app-config: rust.include-dev-dependencies
	IncludeDevDependencies bool `json:"include-dev-dependencies" yaml:"include-dev-dependencies" mapstructure:"include-dev-dependencies"`
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{IncludeDevDependencies: true}
}

func (c CatalogerConfig) WithIncludeDevDependencies(include bool) CatalogerConfig {
	c.IncludeDevDependencies = include
	return c
}

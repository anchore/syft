package julia

type CatalogerConfig struct {
	// IncludeExtras enables including extra dependencies (such as test dependencies) in the catalog results even if they are not installed.
	// app-config: julia.include-extras
	IncludeExtras bool `yaml:"include-extras" json:"include-extras" mapstructure:"include-extras"`
	// IncludeWeakDeps enables including weak dependencies (dependency extensions) in the catalog results even if they are not installed.
	// app-config: julia.include-weakdeps
	IncludeWeakDeps bool `yaml:"include-weakdeps" json:"include-weakdeps" mapstructure:"include-weakdeps"`
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		IncludeExtras:   false,
		IncludeWeakDeps: false,
	}
}

func (c CatalogerConfig) WithIncludeExtras(input bool) CatalogerConfig {
	c.IncludeExtras = input
	return c
}

func (c CatalogerConfig) WithIncludeWeakDeps(input bool) CatalogerConfig {
	c.IncludeWeakDeps = input
	return c
}

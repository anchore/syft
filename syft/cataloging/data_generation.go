package cataloging

type DataGenerationConfig struct {
	GenerateCPEs bool `yaml:"generate-cpes" json:"generate-cpes" mapstructure:"generate-cpes"`
}

func DefaultDataGenerationConfig() DataGenerationConfig {
	return DataGenerationConfig{
		GenerateCPEs: true,
	}
}

func (c DataGenerationConfig) WithGenerateCPEs(generate bool) DataGenerationConfig {
	c.GenerateCPEs = generate
	return c
}

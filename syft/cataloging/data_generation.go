package cataloging

type DataGenerationConfig struct {
	GenerateCPEs          bool `yaml:"generate-cpes" json:"generate-cpes" mapstructure:"generate-cpes"`
	GuessLanguageFromPURL bool `yaml:"guess-language-from-purl" json:"guess-language-from-purl" mapstructure:"guess-language-from-purl"`
}

func DefaultDataGenerationConfig() DataGenerationConfig {
	return DataGenerationConfig{
		GenerateCPEs:          true,
		GuessLanguageFromPURL: true,
	}
}

func (c DataGenerationConfig) WithGenerateCPEs(generate bool) DataGenerationConfig {
	c.GenerateCPEs = generate
	return c
}

func (c DataGenerationConfig) WithGuessLanguageFromPURL(guess bool) DataGenerationConfig {
	c.GuessLanguageFromPURL = guess
	return c
}

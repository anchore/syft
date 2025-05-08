package cataloging

import "github.com/anchore/syft/syft/source"

type SearchConfig struct {
	Scope source.Scope `yaml:"scope" json:"scope" mapstructure:"scope"`
}

func DefaultSearchConfig() SearchConfig {
	return SearchConfig{
		Scope: source.SquashedScope,
	}
}

func (c SearchConfig) WithScope(scope source.Scope) SearchConfig {
	c.Scope = scope
	return c
}

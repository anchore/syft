package options

import (
	"github.com/anchore/syft/syft/source"
)

type fileClassification struct {
	Cataloger Cataloger `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
}

func defaultFileClassification() fileClassification {
	return fileClassification{
		Cataloger: Cataloger{
			Scope: source.SquashedScope.String(),
		},
	}
}

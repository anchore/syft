package options

import (
	"github.com/anchore/syft/syft/source"
)

type fileClassification struct {
	Cataloger catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
}

func fileClassificationDefault() fileClassification {
	return fileClassification{
		Cataloger: catalogerOptions{
			Scope: source.SquashedScope.String(),
		},
	}
}

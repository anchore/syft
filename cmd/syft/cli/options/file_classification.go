package options

import (
	"github.com/anchore/syft/syft/source"
)

type fileClassification struct {
	Cataloger scope `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
}

func defaultFileClassification() fileClassification {
	return fileClassification{
		Cataloger: scope{
			Scope: source.SquashedScope.String(),
		},
	}
}

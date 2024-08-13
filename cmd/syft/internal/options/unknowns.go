package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/cataloging"
)

type unknownsConfig struct {
	ExecutablesWithoutPackages bool `json:"executables-without-packages" yaml:"executables-without-packages" mapstructure:"executables-without-packages"`
	UnexpandedArchives         bool `json:"unexpanded-archives" yaml:"unexpanded-archives" mapstructure:"unexpanded-archives"`
}

var _ interface {
	clio.FieldDescriber
} = (*unknownsConfig)(nil)

func (o *unknownsConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.ExecutablesWithoutPackages, `include executables without any identified packages`)
	descriptions.Add(&o.UnexpandedArchives, `include archives which were not expanded and searched`)
}

func defaultUnknowns() unknownsConfig {
	def := cataloging.DefaultUnknownsConfig()
	return unknownsConfig{
		ExecutablesWithoutPackages: def.IncludeExecutablesWithoutPackages,
		UnexpandedArchives:         def.IncludeUnexpandedArchives,
	}
}

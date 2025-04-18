package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/cataloging"
)

type unknownsConfig struct {
	RemoveWhenPackagesDefined  bool `json:"remove-when-packages-defined" yaml:"remove-when-packages-defined" mapstructure:"remove-when-packages-defined"`
	ExecutablesWithoutPackages bool `json:"executables-without-packages" yaml:"executables-without-packages" mapstructure:"executables-without-packages"`
	UnexpandedArchives         bool `json:"unexpanded-archives" yaml:"unexpanded-archives" mapstructure:"unexpanded-archives"`
}

var _ interface {
	clio.FieldDescriber
} = (*unknownsConfig)(nil)

func (o *unknownsConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.RemoveWhenPackagesDefined, `remove unknown errors on files with discovered packages`)
	descriptions.Add(&o.ExecutablesWithoutPackages, `include executables without any identified packages`)
	descriptions.Add(&o.UnexpandedArchives, `include archives which were not expanded and searched`)
}

func defaultUnknowns() unknownsConfig {
	def := cataloging.DefaultUnknownsConfig()
	return unknownsConfig{
		RemoveWhenPackagesDefined:  def.RemoveWhenPackagesDefined,
		ExecutablesWithoutPackages: def.IncludeExecutablesWithoutPackages,
		UnexpandedArchives:         def.IncludeUnexpandedArchives,
	}
}

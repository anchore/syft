package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
)

type dotnetConfig struct {
	DepPackagesMustHaveDLL bool `mapstructure:"dep-packages-must-have-dll" json:"dep-packages-must-have-dll" yaml:"dep-packages-must-have-dll"`
}

var _ interface {
	clio.FieldDescriber
} = (*dotnetConfig)(nil)

func (o *dotnetConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.DepPackagesMustHaveDLL, `only keep dep.json packages which an executable on disk can be found for`)
}

func defaultDotnetConfig() dotnetConfig {
	def := dotnet.DefaultCatalogerConfig()
	return dotnetConfig{
		DepPackagesMustHaveDLL: def.DepPackagesMustHaveDLL,
	}
}

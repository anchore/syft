package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
)

type dotnetConfig struct {
	DepPackagesMustHaveDLLs bool `mapstructure:"dep-packages-must-have-dlls" json:"dep-packages-must-have-dlls" yaml:"dep-packages-must-have-dlls"`
}

var _ interface {
	clio.FieldDescriber
} = (*dotnetConfig)(nil)

func (o *dotnetConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.DepPackagesMustHaveDLLs, `drop any dep.json packages if there is no DLL file associated with it`)
}

func defaultDotnetConfig() dotnetConfig {
	def := dotnet.DefaultCatalogerConfig()
	return dotnetConfig{
		DepPackagesMustHaveDLLs: def.DepPackagesMustHaveDLLs,
	}
}

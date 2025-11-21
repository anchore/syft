package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
)

type linuxKernelConfig struct {
	CatalogModules bool `json:"catalog-modules" yaml:"catalog-modules" mapstructure:"catalog-modules"`
}

func defaultLinuxKernelConfig() linuxKernelConfig {
	def := kernel.DefaultLinuxKernelCatalogerConfig()
	return linuxKernelConfig{
		CatalogModules: def.CatalogModules,
	}
}

var _ interface {
	clio.FieldDescriber
} = (*linuxKernelConfig)(nil)

func (o *linuxKernelConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.CatalogModules, `whether to catalog linux kernel modules found within lib/modules/** directories`)
}

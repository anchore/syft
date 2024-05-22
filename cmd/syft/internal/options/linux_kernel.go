package options

import "github.com/anchore/clio"

type linuxKernelConfig struct {
	CatalogModules bool `json:"catalog-modules" yaml:"catalog-modules" mapstructure:"catalog-modules"`
}

func defaultLinuxKernelConfig() linuxKernelConfig {
	return linuxKernelConfig{
		CatalogModules: true,
	}
}

var _ interface {
	clio.FieldDescriber
} = (*linuxKernelConfig)(nil)

func (o *linuxKernelConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.CatalogModules, `whether to catalog linux kernel modules found within lib/modules/** directories`)
}

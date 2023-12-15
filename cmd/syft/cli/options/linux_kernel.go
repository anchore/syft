package options

type linuxKernelConfig struct {
	CatalogModules bool `json:"catalog-modules" yaml:"catalog-modules" mapstructure:"catalog-modules"`
}

func defaultLinuxKernel() linuxKernelConfig {
	return linuxKernelConfig{
		CatalogModules: true,
	}
}

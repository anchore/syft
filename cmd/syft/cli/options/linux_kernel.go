package options

type linuxKernelConfig struct {
	CatalogModules bool `json:"catalog-modules" yaml:"catalog-modules" mapstructure:"catalog-modules"`
}

func defaultLinuxKernelConfig() linuxKernelConfig {
	return linuxKernelConfig{
		CatalogModules: true,
	}
}

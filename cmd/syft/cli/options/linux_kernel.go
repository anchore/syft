package options

type linuxKernel struct {
	CatalogModules bool `json:"catalog-modules" yaml:"catalog-modules" mapstructure:"catalog-modules"`
}

func linuxKernelDefault() linuxKernel {
	return linuxKernel{
		CatalogModules: true,
	}
}

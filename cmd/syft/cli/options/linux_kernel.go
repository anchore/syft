package options

type linuxKernel struct {
	CatalogModules bool `json:"catalog-modules" yaml:"catalog-modules" mapstructure:"catalog-modules"`
}

func defaultLinuxKernel() linuxKernel {
	return linuxKernel{
		CatalogModules: true,
	}
}

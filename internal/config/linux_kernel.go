package config

type linuxKernel struct {
	CatalogModules bool `json:"catalog-modules" yaml:"catalog-modules" mapstructure:"catalog-modules"`
}

func newLinuxKernel() linuxKernel {
	return linuxKernel{
		CatalogModules: true,
	}
}

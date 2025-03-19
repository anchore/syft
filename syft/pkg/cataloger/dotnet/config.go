package dotnet

type CatalogerConfig struct {
	DepPackagesMustHaveDLLs bool `mapstructure:"dep-packages-must-have-dlls" json:"dep-packages-must-have-dlls" yaml:"dep-packages-must-have-dlls"`
}

func (c CatalogerConfig) WithDepPackagesMustHaveDLLs(requireDlls bool) CatalogerConfig {
	c.DepPackagesMustHaveDLLs = requireDlls
	return c
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		DepPackagesMustHaveDLLs: false,
	}
}

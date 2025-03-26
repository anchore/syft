package dotnet

type CatalogerConfig struct {
	DepPackagesMustHaveDLL  bool `mapstructure:"dep-packages-must-have-dll" json:"dep-packages-must-have-dll" yaml:"dep-packages-must-have-dll"`
	DepPackagesMustClaimDLL bool `mapstructure:"dep-packages-must-claim-dll" json:"dep-packages-must-claim-dll" yaml:"dep-packages-must-claim-dll"`
}

func (c CatalogerConfig) WithDepPackagesMustHaveDLL(requireDlls bool) CatalogerConfig {
	c.DepPackagesMustHaveDLL = requireDlls
	return c
}

func (c CatalogerConfig) WithDepPackagesMustClaimDLL(requireDlls bool) CatalogerConfig {
	c.DepPackagesMustClaimDLL = requireDlls
	return c
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		DepPackagesMustHaveDLL:  false,
		DepPackagesMustClaimDLL: true,
	}
}

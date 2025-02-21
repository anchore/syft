package dotnet

type CatalogerConfig struct {
	EnableCertificateValidation bool
}

func (c CatalogerConfig) WithCertificateValidation(enable bool) CatalogerConfig {
	c.EnableCertificateValidation = enable
	return c
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{}
}

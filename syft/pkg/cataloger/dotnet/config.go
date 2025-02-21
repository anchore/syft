package dotnet

type CatalogerConfig struct {
	EnableCertificateValidation bool `json:"enable-certificate-validation" yaml:"enable-certificate-validation" mapstructure:"enable-certificate-validation"`
}

func (c CatalogerConfig) WithCertificateValidation(enable bool) CatalogerConfig {
	c.EnableCertificateValidation = enable
	return c
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{}
}

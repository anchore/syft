package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
)

type dotnetConfig struct {
	EnableCertificateValidation bool `json:"enable-certificate-validation" yaml:"enable-certificate-validation" mapstructure:"enable-certificate-validation"`
}

var _ interface {
	clio.FieldDescriber
} = (*dotnetConfig)(nil)

func (o *dotnetConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.EnableCertificateValidation, `enable certificate validation -- this requires an active internet connection to download certificates and CRLs`)
}

func defaultDotnetConfig() dotnetConfig {
	def := dotnet.DefaultCatalogerConfig()
	return dotnetConfig{
		EnableCertificateValidation: def.EnableCertificateValidation,
	}
}

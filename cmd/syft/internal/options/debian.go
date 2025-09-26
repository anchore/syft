package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/debian"
)

type debianConfig struct {
	IncludeDeInstalled bool `yaml:"include-deinstalled" json:"include-deinstalled" mapstructure:"include-deinstalled"`
}

var _ interface {
	clio.FieldDescriber
} = (*debianConfig)(nil)

func (o *debianConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.IncludeDeInstalled, `include debian packages that have been removed but not purged (deinstall status)
by default these packages are excluded from the SBOM`)
}

func defaultDebianConfig() debianConfig {
	def := debian.DefaultCatalogerConfig()
	return debianConfig{
		IncludeDeInstalled: def.IncludeDeInstalled,
	}
}
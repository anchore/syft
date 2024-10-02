package options

import (
	"github.com/anchore/fangs"
	"github.com/anchore/syft/syft/cataloging"
)

var (
	_ fangs.FieldDescriber = (*complianceConfig)(nil)
	_ fangs.PostLoader     = (*complianceConfig)(nil)
)

type complianceConfig struct {
	MissingName    cataloging.ComplianceAction `mapstructure:"missing-name" json:"missing-name" yaml:"missing-name"`
	MissingVersion cataloging.ComplianceAction `mapstructure:"missing-version" json:"missing-version" yaml:"missing-version"`
}

func defaultComplianceConfig() complianceConfig {
	def := cataloging.DefaultComplianceConfig()
	return complianceConfig{
		MissingName:    def.MissingName,
		MissingVersion: def.MissingVersion,
	}
}

func (r *complianceConfig) DescribeFields(descriptions fangs.FieldDescriptionSet) {
	descriptions.Add(&r.MissingName, "action to take when a package is missing a name")
	descriptions.Add(&r.MissingVersion, "action to take when a package is missing a version")
}

func (r *complianceConfig) PostLoad() error {
	r.MissingName = r.MissingName.Parse()
	r.MissingVersion = r.MissingVersion.Parse()
	return nil
}

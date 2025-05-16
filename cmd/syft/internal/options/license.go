package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/cataloging"
)

type licenseConfig struct {
	Content                 cataloging.LicenseContent   `yaml:"content" json:"content" mapstructure:"content"`
	Coverage                float64                     `yaml:"coverage" json:"coverage" mapstructure:"coverage"`
	AvailableLicenseContent []cataloging.LicenseContent `yaml:"-" json:"-" mapstructure:"-"`
}

var _ interface {
	clio.FieldDescriber
} = (*licenseConfig)(nil)

func (o *licenseConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.Content, fmt.Sprintf("include the content of licenses in the SBOM for a given syft scan; valid values are: %s", o.AvailableLicenseContent))

	descriptions.Add(&o.Coverage, `adjust the percent as a fraction of the total text, in normalized words, that
matches any valid license for the given inputs, expressed as a percentage across all of the licenses matched.`)
}

func (o *licenseConfig) PostLoad() error {
	validContent := internal.NewSet(o.AvailableLicenseContent...)
	if !validContent.Contains(o.Content) {
		return fmt.Errorf("could not use %q as license content option; valid values are: %v", o.Content, validContent.ToSlice())
	}
	return nil
}

func defaultLicenseConfig() licenseConfig {
	cfg := cataloging.DefaultLicenseConfig()
	return licenseConfig{
		Content:  cfg.IncludeContent,
		Coverage: cfg.Coverage,
		AvailableLicenseContent: []cataloging.LicenseContent{
			cataloging.LicenseContentIncludeAll,
			cataloging.LicenseContentIncludeUnknown,
			cataloging.LicenseContentExcludeAll,
		},
	}
}

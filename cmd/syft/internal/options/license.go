package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/cataloging"
)

type licenseConfig struct {
	Content cataloging.LicenseContent `yaml:"content" json:"content" mapstructure:"content"`
	// Deprecated: please use include-license-content instead
	IncludeUnknownLicenseContent *bool `yaml:"-" json:"-" mapstructure:"include-unknown-license-content"`

	Coverage float64 `yaml:"coverage" json:"coverage" mapstructure:"coverage"`
	// Deprecated: please use coverage instead
	LicenseCoverage *float64 `yaml:"license-coverage" json:"license-coverage" mapstructure:"license-coverage"`

	AvailableLicenseContent []cataloging.LicenseContent `yaml:"-" json:"-" mapstructure:"-"`
}

var _ interface {
	clio.FieldDescriber
} = (*licenseConfig)(nil)

func (o *licenseConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.Content, fmt.Sprintf("include the content of licenses in the SBOM for a given syft scan; valid values are: %s", o.AvailableLicenseContent))
	descriptions.Add(&o.IncludeUnknownLicenseContent, `deprecated: please use 'license-content' instead`)

	descriptions.Add(&o.Coverage, `adjust the percent as a fraction of the total text, in normalized words, that
matches any valid license for the given inputs, expressed as a percentage across all of the licenses matched.`)
	descriptions.Add(&o.LicenseCoverage, `deprecated: please use 'coverage' instead`)
}

func (o *licenseConfig) PostLoad() error {
	cfg := cataloging.DefaultLicenseConfig()
	defaultContent := cfg.IncludeContent
	defaultCoverage := cfg.Coverage

	// if both legacy and new fields are specified, error out
	if o.IncludeUnknownLicenseContent != nil && o.Content != defaultContent {
		return fmt.Errorf("both 'include-unknown-license-content' and 'content' are set, please use only 'content'")
	}

	if o.LicenseCoverage != nil && o.Coverage != defaultCoverage {
		return fmt.Errorf("both 'license-coverage' and 'coverage' are set, please use only 'coverage'")
	}

	// finalize the license content value
	if o.IncludeUnknownLicenseContent != nil {
		// convert 'include-unknown-license-content' -> 'license-content'
		v := cataloging.LicenseContentExcludeAll
		if *o.IncludeUnknownLicenseContent {
			v = cataloging.LicenseContentIncludeUnknown
		}
		o.Content = v
	}

	// finalize the coverage value
	if o.LicenseCoverage != nil {
		// convert 'license-coverage' -> 'coverage'
		o.Coverage = *o.LicenseCoverage
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

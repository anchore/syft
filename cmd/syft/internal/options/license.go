package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/cataloging"
)

type licenseConfig struct {
	// Deprecated: please use include-license-content instead
	IncludeUnknownLicenseContent *bool                      `yaml:"-" json:"-" mapstructure:"include-unknown-license-content"`
	LicenseContent               *cataloging.LicenseContent `yaml:"license-content" json:"license-content" mapstructure:"license-content"`
	LicenseCoverage              float64                    `yaml:"license-coverage" json:"license-coverage" mapstructure:"license-coverage"`

	AvailableLicenseContent []cataloging.LicenseContent `yaml:"-" json:"-" mapstructure:"-"`
}

var _ interface {
	clio.FieldDescriber
} = (*licenseConfig)(nil)

func (o *licenseConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.IncludeUnknownLicenseContent, `deprecated: include the content of a license in the SBOM when syft
cannot determine a valid SPDX ID for the given license`)
	descriptions.Add(&o.LicenseContent, fmt.Sprintf("include the content of licenses in the SBOM for a given syft scan; valid values are: %s", o.AvailableLicenseContent))
	descriptions.Add(&o.LicenseCoverage, `adjust the percent as a fraction of the total text, in normalized words, that
matches any valid license for the given inputs, expressed as a percentage across all of the licenses matched.`)
}

func (o *licenseConfig) PostLoad() error {
	// if both are specified, prefer the new field
	if o.IncludeUnknownLicenseContent != nil && o.LicenseContent != nil {
		return fmt.Errorf("both 'include-unknown-license-content' and 'license-content' are set, please use only 'license-content'")
	}

	// convert the old field to the new field
	if o.IncludeUnknownLicenseContent != nil {
		v := cataloging.LicenseContentExcludeAll
		if *o.IncludeUnknownLicenseContent {
			v = cataloging.LicenseContentIncludeUnknown
		}
		o.LicenseContent = &v
	}

	return nil
}

func defaultLicenseConfig() licenseConfig {
	cfg := cataloging.DefaultLicenseConfig()
	return licenseConfig{
		LicenseContent: &cfg.IncludeContent,
		AvailableLicenseContent: []cataloging.LicenseContent{
			cataloging.LicenseContentIncludeAll,
			cataloging.LicenseContentIncludeUnknown,
			cataloging.LicenseContentExcludeAll,
		},
		LicenseCoverage: cfg.Coverage,
	}
}

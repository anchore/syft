package options

import (
	"github.com/anchore/clio"
)

type licenseConfig struct {
	IncludeUnknownLicenseContent bool    `yaml:"include-unknown-license-content" json:"include-unknown-license-content" mapstructure:"include-unknown-license-content"`
	LicenseCoverage              float64 `yaml:"license-coverage" json:"license-coverage" mapstructure:"license-coverage"`
}

var _ interface {
	clio.FieldDescriber
} = (*licenseConfig)(nil)

func (o *licenseConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.IncludeUnknownLicenseContent, `include the content of a license in the SBOM when syft
cannot determine a valid SPDX ID for the given license`)
	descriptions.Add(&o.LicenseCoverage, `adjust the percent as a fraction of the total text, in normalized words, that
matches any valid license for the given inputs, expressed as a percentage across all of the licenses matched.`)
}

func defaultLicenseConfig() licenseConfig {
	return licenseConfig{
		IncludeUnknownLicenseContent: false,
		LicenseCoverage:              75,
	}
}

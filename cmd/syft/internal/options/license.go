package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/log"
)

type licenseConfig struct {
	// Deprecated: please use include-license-content instead
	IncludeUnknownLicenseContent bool    `yaml:"include-unknown-license-content" json:"include-unknown-license-content" mapstructure:"include-unknown-license-content"`
	IncludeLicenseContent        string  `yaml:"include-license-content" json:"include-license-content" mapstructure:"include-license-content"`
	LicenseCoverage              float64 `yaml:"license-coverage" json:"license-coverage" mapstructure:"license-coverage"`
}

var _ interface {
	clio.FieldDescriber
} = (*licenseConfig)(nil)

func (o *licenseConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.IncludeUnknownLicenseContent, `deprecated: include the content of a license in the SBOM when syft
cannot determine a valid SPDX ID for the given license`)
	descriptions.Add(&o.IncludeLicenseContent, `include the content of licenses in the SBOM for a given syft scan; valid values are: all, unknown, or none; default is none`)
	descriptions.Add(&o.LicenseCoverage, `adjust the percent as a fraction of the total text, in normalized words, that
matches any valid license for the given inputs, expressed as a percentage across all of the licenses matched.`)
}

func (o *licenseConfig) PostLoad() error {
	if o.IncludeUnknownLicenseContent && (o.IncludeLicenseContent == "none" || o.IncludeLicenseContent == "all") {
		log.Warnf("ignoring deprecated option: include-unknown-license-content=%t infavor of include-license-content=%s", o.IncludeUnknownLicenseContent, o.IncludeLicenseContent)
		log.Warnf("please update your configuration to use include-license-content option")
	}
	return nil
}

func defaultLicenseConfig() licenseConfig {
	return licenseConfig{
		IncludeUnknownLicenseContent: false,
		IncludeLicenseContent:        "none",
		LicenseCoverage:              75,
	}
}

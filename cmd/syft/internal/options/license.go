package options

import (
	"github.com/anchore/clio"
)

type licenseConfig struct {
	IncludeUnknownLicenseContent bool `yaml:"include-unknown-license-content" json:"include-unknown-license-content" mapstruct:"include-unknown-license-content"`
}

var _ interface {
	clio.FieldDescriber
} = (*licenseConfig)(nil)

func (o *licenseConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.IncludeUnknownLicenseContent, `include the content of a license in the SBOM when syft
cannot determine a valid SPDX ID for the given license`)
}

func defaultLicenseConfig() licenseConfig {
	return licenseConfig{
		IncludeUnknownLicenseContent: false,
	}
}

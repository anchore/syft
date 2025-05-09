package cataloging

import "github.com/anchore/syft/internal/licenses"

type LicenseConfig struct {
	IncludeFullText              bool    `json:"include-full-text" yaml:"include-full-text" mapstructure:"include-full-text"`
	IncludeUnknownLicenseContent bool    `json:"include-unknown-license-content" yaml:"include-unknown-license-content" mapstructure:"include-unknown-license-content"`
	Coverage                     float64 `json:"coverage" yaml:"coverage" mapstructure:"coverage"`
}

func DefaultLicenseConfig() LicenseConfig {
	return LicenseConfig{
		IncludeFullText:              licenses.DefaultIncludeFullText,
		IncludeUnknownLicenseContent: licenses.DefaultIncludeUnknownLicenseContent,
		Coverage:                     licenses.DefaultCoverageThreshold,
	}
}

package cataloging

import (
	"github.com/anchore/syft/internal/licenses"
)

// LicenseContent controls when license content should be included in the SBOM.
type LicenseContent string

const (
	LicenseContentIncludeAll     LicenseContent = "all"
	LicenseContentIncludeUnknown LicenseContent = "unknown"
	LicenseContentExcludeAll     LicenseContent = "none"
)

type LicenseConfig struct {
	// IncludeContent controls whether license copy discovered should be included in the SBOM.
	IncludeContent LicenseContent `json:"include-content" yaml:"include-content" mapstructure:"include-content"`

	// Coverage is the percentage of text that must match a license for it to be considered a match.
	Coverage float64 `json:"coverage" yaml:"coverage" mapstructure:"coverage"`
}

func DefaultLicenseConfig() LicenseConfig {
	return LicenseConfig{
		IncludeContent: LicenseContentExcludeAll,
		Coverage:       licenses.DefaultCoverageThreshold,
	}
}

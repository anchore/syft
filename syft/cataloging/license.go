package cataloging

import (
	"github.com/anchore/syft/internal/licenses"
)

// IncludeLicenseContent controls whether license content should be included.
type IncludeLicenseContent string

const (
	IncludeLicenseContentAll     IncludeLicenseContent = "all"
	IncludeLicenseContentUnknown IncludeLicenseContent = "unknown"
	IncludeLicenseContentNone    IncludeLicenseContent = "none"
)

type LicenseConfig struct {
	// Deprecated: use IncludeLicenseContent instead
	IncludeUnkownLicenseContent bool                  `json:"include-unknown-license-content" yaml:"include-unknown-license-content" mapstructure:"include-unknown-license-content"`
	IncludeLicenseContent       IncludeLicenseContent `json:"include-license-content" yaml:"include-license-content" mapstructure:"include-license-content"`
	Coverage                    float64               `json:"coverage" yaml:"coverage" mapstructure:"coverage"`
}

func DefaultLicenseConfig() LicenseConfig {
	return LicenseConfig{
		IncludeLicenseContent: IncludeLicenseContentNone,
		Coverage:              licenses.DefaultCoverageThreshold,
	}
}

// ParseIncludeLicenseContent converts a string to IncludeLicenseContent and validates it.
func ParseIncludeLicenseContent(s string) IncludeLicenseContent {
	val := IncludeLicenseContent(s)
	if !val.IsValid() {
		return IncludeLicenseContentNone
	}
	return val
}

func (i IncludeLicenseContent) IsValid() bool {
	switch i {
	case IncludeLicenseContentAll, IncludeLicenseContentUnknown, IncludeLicenseContentNone:
		return true
	default:
		return false
	}
}

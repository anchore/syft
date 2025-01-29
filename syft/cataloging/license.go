package cataloging

import "github.com/anchore/syft/internal/licenses"

type LicenseConfig struct {
	IncludeUnkownLicenseContent bool
	Coverage                    float64
}

func DefaultLicenseConfig() LicenseConfig {
	return LicenseConfig{
		IncludeUnkownLicenseContent: false,
		Coverage:                    licenses.DefaultCoverageThreshold,
	}
}

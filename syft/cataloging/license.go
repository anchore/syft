package cataloging

import "github.com/anchore/syft/internal/licenses"

type LicenseConfig struct {
	IncludeUnkownLicenseContent bool    `json:"include-unknown-license-content" yaml:"include-unknown-license-content" mapstructure:"include-unknown-license-content"`
	Coverage                    float64 `json:"coverage" yaml:"coverage" mapstructure:"coverage"`
}

func DefaultLicenseConfig() LicenseConfig {
	return LicenseConfig{
		IncludeUnkownLicenseContent: licenses.DefaultIncludeLicenseContent,
		Coverage:                    licenses.DefaultCoverageThreshold,
	}
}

// GetContextKey allows callers to access the key used by
// syft to store the license scanner in the context
func GetContextKey() licenses.LicenseScannerKey {
	return licenses.CtxKey
}

// NewDefaultLicenseScanner creates a default license scanner and exists
// to export NewDefaultScanner to those who use Syft as a library.
func NewDefaultLicenseScanner(o ...licenses.Option) (licenses.Scanner, error) {
	return licenses.NewDefaultScanner(o...)
}

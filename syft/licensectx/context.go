package licensectx

import "github.com/anchore/syft/internal/licenses"

func GetContextKey() licenses.LicenseScannerKey {
	return licenses.LicenseScannerKey{}
}

// NewDefaultLicenseScanner creates a default license scanner and exists
// to export NewDefaultScanner to those who use Syft as a library.
func NewDefaultLicenseScanner(o ...licenses.Option) (licenses.Scanner, error) {
	return licenses.NewDefaultScanner(o...)
}

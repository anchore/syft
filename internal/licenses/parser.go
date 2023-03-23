package licenses

import (
	"io"

	"github.com/google/licensecheck"
	"golang.org/x/exp/slices"
)

const (
	coverageThreshold  = 75
	unknownLicenseType = "UNKNOWN"
)

// Parse scans the contents of a license file to attempt to determine the type of license it is
func Parse(reader io.Reader) (licenses []string, err error) {
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	cov := licensecheck.Scan(contents)

	if cov.Percent < float64(coverageThreshold) {
		licenses = append(licenses, unknownLicenseType)
	}
	for _, m := range cov.Match {
		if slices.Contains(licenses, m.ID) {
			continue
		}
		licenses = append(licenses, m.ID)
	}
	return
}

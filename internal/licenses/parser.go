package licenses

import (
	"io"

	"github.com/google/licensecheck"

	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const (
	coverageThreshold  = 75
	unknownLicenseType = "UNKNOWN"
)

// Parse scans the contents of a license file to attempt to determine the type of license it is
func Parse(reader io.Reader, l source.Location) (licenses []pkg.License, err error) {
	licenses = make([]pkg.License, 0)
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	cov := licensecheck.Scan(contents)
	if cov.Percent < coverageThreshold {
		// unknown or no licenses here?
		return licenses, nil
	}

	for _, m := range cov.Match {
		// TODO: spdx ID validation here?
		lic := pkg.NewLicense(m.ID, l)
		lic.Type = license.Concluded

		licenses = append(licenses, lic)
	}

	return licenses, nil
}

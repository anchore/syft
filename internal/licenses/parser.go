package licenses

import (
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/google/licensecheck"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

const (
	coverageThreshold    = 75
	unknownLicenseType   = "UNKNOWN"
	UnknownLicensePrefix = unknownLicenseType + "_"
)

func getCustomLicenseContentHash(contents []byte) string {
	hash := sha256.Sum256(contents)
	return fmt.Sprintf("%x", hash[:])
}

// Parse scans the contents of a license file to attempt to determine the type of license it is
func Parse(reader io.Reader, l file.Location) (licenses []pkg.License, err error) {
	licenses = make([]pkg.License, 0)
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	scanner, err := licensecheck.NewScanner(licensecheck.BuiltinLicenses())
	if err != nil {
		return nil, err
	}

	cov := scanner.Scan(contents)
	if cov.Percent < coverageThreshold {
		// unknown or no licenses here?
		if len(contents) > 0 {
			// harmonize line endings to unix compatible first:
			// 1. \r\n => \n   (Windows   => UNIX)
			// 2. \r   => \n   (Macintosh => UNIX)
			contents = []byte(strings.ReplaceAll(strings.ReplaceAll(string(contents), "\r\n", "\n"), "\r", "\n"))

			lic := pkg.NewLicenseFromLocations(unknownLicenseType, l)
			lic.SPDXExpression = UnknownLicensePrefix + getCustomLicenseContentHash(contents)
			lic.Contents = string(contents)
			lic.Type = license.Declared

			licenses = append(licenses, lic)
		}

		return licenses, nil
	}

	for _, m := range cov.Match {
		lic := pkg.NewLicenseFromLocations(m.ID, l)
		lic.Type = license.Concluded

		licenses = append(licenses, lic)
	}

	return licenses, nil
}

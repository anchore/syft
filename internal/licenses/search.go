package licenses

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

const (
	unknownLicenseType   = "UNKNOWN"
	UnknownLicensePrefix = unknownLicenseType + "_"
)

func getCustomLicenseContentHash(contents []byte) string {
	hash := sha256.Sum256(contents)
	return fmt.Sprintf("%x", hash[:])
}

// Search scans the contents of a license file to attempt to determine the type of license it is
func Search(ctx context.Context, scanner Scanner, reader file.LocationReadCloser) (licenses []pkg.License, err error) {
	licenses = make([]pkg.License, 0)

	ids, content, err := scanner.IdentifyLicenseIDs(ctx, reader)
	if err != nil {
		return nil, err
	}

	if len(ids) > 0 {
		for _, id := range ids {
			lic := pkg.NewLicenseFromLocations(id, reader.Location)
			lic.Type = license.Concluded

			licenses = append(licenses, lic)
		}
	} else if len(content) > 0 {
		// harmonize line endings to unix compatible first:
		// 1. \r\n => \n   (Windows   => UNIX)
		// 2. \r   => \n   (Macintosh => UNIX)
		content = []byte(strings.ReplaceAll(strings.ReplaceAll(string(content), "\r\n", "\n"), "\r", "\n"))

		lic := pkg.NewLicenseFromLocations(unknownLicenseType, reader.Location)
		lic.SPDXExpression = UnknownLicensePrefix + getCustomLicenseContentHash(content)
		lic.Contents = string(content)
		lic.Type = license.Declared

		licenses = append(licenses, lic)
	}

	return licenses, nil
}

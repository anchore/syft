package licenses

import (
	"context"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

// Search scans the contents of a license file to attempt to determine the type of license it is
func Search(ctx context.Context, scanner Scanner, reader file.LocationReadCloser) (licenses []pkg.License, err error) {
	licenses = make([]pkg.License, 0)

	ids, err := scanner.IdentifyLicenseIDs(ctx, reader)
	if err != nil {
		return nil, err
	}

	for _, id := range ids {
		lic := pkg.NewLicenseFromLocations(id, reader.Location)
		lic.Type = license.Concluded

		licenses = append(licenses, lic)
	}

	return licenses, nil
}

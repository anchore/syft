package licenses

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
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

func (s *scanner) IdentifyLicenseIDs(_ context.Context, reader io.Reader) ([]string, []byte, error) {
	if s.scanner == nil {
		return nil, nil, nil
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}

	cov := s.scanner(content)
	if cov.Percent < s.coverageThreshold {
		// unknown or no licenses here
		// => check return content to Search to process
		return nil, content, nil
	}

	var ids []string
	for _, m := range cov.Match {
		ids = append(ids, m.ID)
	}
	return ids, nil, nil
}

// PkgSearch scans the contents of a license file to attempt to determine the type of license it is
func (s *scanner) PkgSearch(ctx context.Context, reader file.LocationReadCloser) (licenses []pkg.License, err error) {
	licenses = make([]pkg.License, 0)

	ids, content, err := s.IdentifyLicenseIDs(ctx, reader)
	if err != nil {
		return nil, err
	}

	// IdentifyLicenseIDs can only return a list of ID or content
	// These return values are mutually exclusive.
	// If the scanner threshold for matching scores < 75% then we return the license full content
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
		if s.includeLicenseContent {
			lic.Contents = string(content)
		}
		lic.Type = license.Declared

		licenses = append(licenses, lic)
	}

	return licenses, nil
}

// FileSearch scans the contents of a license file to attempt to determine the type of license it is
func (s *scanner) FileSearch(ctx context.Context, reader file.LocationReadCloser) (licenses []file.License, err error) {
	licenses = make([]file.License, 0)

	ids, content, err := s.IdentifyLicenseIDs(ctx, reader)
	if err != nil {
		return nil, err
	}

	// IdentifyLicenseIDs can only return a list of ID or content
	// These return values are mutually exclusive.
	// If the scanner threshold for matching scores < 75% then we return the license full content
	if len(ids) > 0 {
		for _, id := range ids {
			lic := file.NewLicense(id)
			lic.Type = license.Concluded

			licenses = append(licenses, lic)
		}
	} else if len(content) > 0 {
		// harmonize line endings to unix compatible first:
		// 1. \r\n => \n   (Windows   => UNIX)
		// 2. \r   => \n   (Macintosh => UNIX)
		content = []byte(strings.ReplaceAll(strings.ReplaceAll(string(content), "\r\n", "\n"), "\r", "\n"))

		lic := file.NewLicense(unknownLicenseType)
		lic.SPDXExpression = UnknownLicensePrefix + getCustomLicenseContentHash(content)
		if s.includeLicenseContent {
			lic.Contents = string(content)
		}
		lic.Type = license.Declared

		licenses = append(licenses, lic)
	}

	return licenses, nil
}

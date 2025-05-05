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

func (s *scanner) IdentifyLicenseIDs(_ context.Context, reader io.Reader) ([]ID, []byte, error) {
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

	var ids []ID
	for _, m := range cov.Match {
		ids = append(ids, ID{LicenseID: m.ID, Offset: Offset{Start: m.Start, End: m.End}})
	}

	// sometimes users want the full license even if they got an SPDX ID from searching the content
	if s.includeFullText {
		return ids, content, nil
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

	// known licenses found
	if len(ids) > 0 {
		for _, id := range ids {
			if s.includeFullText {
				extracted := string(content[id.Offset.Start:id.Offset.End])
				licenses = append(licenses, pkg.NewLicenseFromFullText(id.LicenseID, fixLineEndings(extracted), reader.Location, license.Concluded))
			} else {
				li := pkg.NewLicenseFromType(id.LicenseID, license.Concluded)
				li.Locations.Add(reader.Location)
				licenses = append(licenses, li)
			}
		}
		return licenses, nil
	}

	// scanner could not find SPDX ID associated with content
	lic := pkg.NewLicenseFromLocations(unknownLicenseType, reader.Location)
	lic.SPDXExpression = UnknownLicensePrefix + getCustomLicenseContentHash(content)
	lic.Type = license.Declared
	if s.includeUnknownLicenseContent {
		lic.FullText = fixLineEndings(string(content))
	}
	licenses = append(licenses, lic)

	return licenses, nil
}

// FileSearch scans the contents of a license file to attempt to determine the type of license it is
func (s *scanner) FileSearch(ctx context.Context, reader file.LocationReadCloser) (licenses []file.License, err error) {
	licenses = make([]file.License, 0)

	ids, content, err := s.IdentifyLicenseIDs(ctx, reader)
	if err != nil {
		return nil, err
	}

	if len(ids) > 0 {
		for _, id := range ids {
			lic := file.NewLicense(id.LicenseID)
			lic.Type = license.Concluded
			if s.includeFullText {
				extracted := string(content[id.Offset.Start:id.Offset.End])
				lic.Contents = fixLineEndings(extracted)
			}
			licenses = append(licenses, lic)
		}
		return licenses, nil
	}

	lic := file.NewLicense(unknownLicenseType)
	lic.SPDXExpression = UnknownLicensePrefix + getCustomLicenseContentHash(content)
	if s.includeUnknownLicenseContent {
		lic.Contents = fixLineEndings(string(content))
	}

	lic.Type = license.Declared
	licenses = append(licenses, lic)

	return licenses, nil
}

func fixLineEndings(content string) string {
	// harmonize line endings to unix compatible first:
	// 1. \r\n => \n   (Windows   => UNIX)
	// 2. \r   => \n   (Macintosh => UNIX)
	return strings.ReplaceAll(strings.ReplaceAll(content, "\r\n", "\n"), "\r", "\n")
}

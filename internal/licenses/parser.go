package licenses

import (
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/licensecheck"
)

const (
	coverageThreshold  = 75
	unknownLicenseType = "UNKNOWN"
)

// ScanLicenses scan an fs.FS for licenses, First finds files that fit with the list
// in FileNames, and then uses github.com/google/licensecheck to scan the contents.
func ScanLicenses(fsys fs.FS) []string {
	var (
		licenses []string
		isVendor bool
	)
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		filename := filepath.Base(p)
		// ignore any tat are not a known filetype
		if _, ok := fileNames[filename]; !ok {
			return nil
		}
		// make sure it is not in a vendored path
		parts := strings.Split(filepath.Dir(p), string(filepath.Separator))
		for _, part := range parts {
			if part == "vendor" {
				isVendor = true
				break
			}
		}
		if isVendor {
			return nil
		}
		// read the file contents
		rc, err := fsys.Open(p)
		if err != nil {
			return nil
		}
		defer rc.Close()
		contents, err := io.ReadAll(rc)
		if err != nil {
			return nil
		}
		cov := licensecheck.Scan(contents)

		if cov.Percent < float64(coverageThreshold) {
			licenses = append(licenses, unknownLicenseType)
		}
		for _, m := range cov.Match {
			licenses = append(licenses, m.ID)
		}
		return nil
	})
	return licenses
}

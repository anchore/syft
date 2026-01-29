package spdxlicense

import (
	"strings"
)

// https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-short-name
// License generated in license_list.go uses a regular expression to help resolve cases where
// x.0.0 and x are supplied as version numbers. For SPDX compatibility, versions with trailing
// dot-zeroes are considered to be equivalent to versions without (e.g., “2.0.0” is considered equal to “2.0” and “2”).
// EX: gpl-2+ ---> GPL-2.0+
// EX: gpl-2.0.0-only ---> GPL-2.0-only
// See the debian link for more details on the spdx license differences

const (
	LicenseRefPrefix = "LicenseRef-" // prefix for non-standard licenses
)

//go:generate go run ./generate

// ID returns the canonical license ID for the given license ID
// Note: this function is only concerned with returning a best match of an SPDX license ID
// SPDX Expressions will be handled by a parent package which will call this function
func ID(id string) (value string, exists bool) {
	// first look for a canonical license
	if value, exists := licenseIDs[cleanLicenseID(id)]; exists {
		return value, exists
	}
	// we did not find, so treat it as a separate license
	return "", false
}

func cleanLicenseID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.ToLower(id)
	return strings.ReplaceAll(id, "-", "")
}

// LicenseInfo contains license ID and name
type LicenseInfo struct {
	ID string
}

// LicenseByURL returns the license ID for a given URL.
// It first checks supplemental mappings (user-contributed URLs not in the official
// SPDX list), then the auto-generated SPDX license list mappings.
func LicenseByURL(url string) (LicenseInfo, bool) {
	url = strings.TrimSpace(url)

	// Check supplemental mappings first (user-contributed URLs)
	if id, exists := supplementalURLToLicense[url]; exists {
		return LicenseInfo{ID: id}, true
	}

	// Fall back to auto-generated SPDX mappings
	if id, exists := urlToLicense[url]; exists {
		return LicenseInfo{ID: id}, true
	}

	return LicenseInfo{}, false
}

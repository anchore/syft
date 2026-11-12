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

// LicenseByURL returns the license ID and name for a given URL from the SPDX license list.
// The URL should match one of the URLs in the seeAlso field of an SPDX license.
// The scheme (http:// or https://) is stripped before lookup, so both schemes match.
// opensource.org URLs additionally match regardless of the form used (see normalizeOpenSourceOrgURL).
func LicenseByURL(url string) (LicenseInfo, bool) {
	url = strings.TrimSpace(url)
	url = stripScheme(url)
	if id, exists := urlToLicense[url]; exists {
		return LicenseInfo{
			ID: id,
		}, true
	}
	if normalized, ok := normalizeOpenSourceOrgURL(url); ok {
		if id, exists := openSourceOrgURLToLicense[normalized]; exists {
			return LicenseInfo{
				ID: id,
			}, true
		}
	}
	return LicenseInfo{}, false
}

// openSourceOrgURLToLicense indexes the opensource.org entries of urlToLicense by normalized URL.
var openSourceOrgURLToLicense = buildOpenSourceOrgURLToLicense(urlToLicense)

func buildOpenSourceOrgURLToLicense(urls map[string]string) map[string]string {
	index := make(map[string]string)
	ambiguous := make(map[string]bool)
	for url, id := range urls {
		normalized, ok := normalizeOpenSourceOrgURL(url)
		if !ok || ambiguous[normalized] {
			continue
		}
		if existing, exists := index[normalized]; exists && existing != id {
			// don't guess between licenses that only differ by URL form
			delete(index, normalized)
			ambiguous[normalized] = true
			continue
		}
		index[normalized] = id
	}
	return index
}

// normalizeOpenSourceOrgURL reduces a scheme-less opensource.org URL to a canonical form.
// SPDX has changed these URLs over time (e.g. 3.29.0 replaced opensource.org/licenses/MIT and
// opensource.org/license/mit/ with opensource.org/license/MIT), while package metadata in the wild
// still uses the older forms. The www. prefix, /licenses/ vs /license/, case, and trailing slash are ignored.
func normalizeOpenSourceOrgURL(url string) (string, bool) {
	url = strings.TrimPrefix(strings.ToLower(url), "www.")
	if !strings.HasPrefix(url, "opensource.org/") {
		return "", false
	}
	url = strings.Replace(url, "opensource.org/licenses/", "opensource.org/license/", 1)
	return strings.TrimSuffix(url, "/"), true
}

// stripScheme removes http:// or https:// prefix from a URL.
// This allows a single map entry to match both schemes.
func stripScheme(url string) string {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	return url
}

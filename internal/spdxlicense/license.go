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

func ID(id string) (value, other string, exists bool) {
	id = strings.TrimSpace(id)
	// ignore blank strings or the joiner
	if id == "" || id == "AND" || id == "OR" {
		return "", "", false
	}
	// first look for a canonical license
	if value, exists := licenseIDs[strings.ToLower(id)]; exists {
		return value, "", exists
	}
	// we did not find, so treat it as a separate license
	return "", id, true
}

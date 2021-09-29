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

//go:generate go run generate/generate_license_list.go

func ID(id string) (string, bool) {
	value, exists := licenseIDs[strings.ToLower(id)]
	return value, exists
}

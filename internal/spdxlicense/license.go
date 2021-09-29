package spdxlicense

import (
	"regexp"
	"strings"
)

// https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-short-name
// If a license generated in license_list.go is not found when looking up by ID,
// then the ID function will use these regular expressions to help resolve cases where
// x.0.0 and x are supplied as version numbers. For SPDX compatibility, versions with trailing
// dot-zeroes are considered to be equivalent to versions without (e.g., “2.0.0” is considered equal to “2.0” and “2”).
// EX: gpl-2+ ---> GPL-2.0+
// EX: gpl-2.0.0-only ---> GPL-2.0-only
// See the debian link for more details on the spdx license differences
var (
	zero   = regexp.MustCompile(`^((.*).0)(.*)$`)
	noZero = regexp.MustCompile(`^(.*-)([1-9])(.*)`)
)

//go:generate go run generate_license_list.go

func ID(id string) (string, bool) {
	var idBytes []byte
	lowerID := strings.ToLower(id)
	value, exists := licenseIDs[lowerID]
	if !exists {
		// check if the license was input with `.0.0`
		if zero.Match([]byte(lowerID)) {
			idBytes = zero.ReplaceAll([]byte(lowerID), []byte("${2}${3}"))
		} else {
			idBytes = noZero.ReplaceAll([]byte(lowerID), []byte("${1}${2}.0${3}"))
		}

		value, exists = licenseIDs[string(idBytes)]
	}
	return value, exists
}

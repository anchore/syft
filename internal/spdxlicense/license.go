package spdxlicense

import (
	"regexp"
	"strings"
)

// https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-short-name
// If a license generated in license_list.go is not found when looking up by ID,
// then the ID function will check this map for short name exceptions as detailed
// in the above link.
var (
	zero   = regexp.MustCompile(`^((.*).0)(.*)$`)
	noZero = regexp.MustCompile(`^(.*-)([1-9])(.*)`)
)

//go:generate go run generate_license_list.go

func ID(id string) (string, bool) {
	var idBytes []byte
	value, exists := licenseIDs[strings.ToLower(id)]
	if !exists {
		// check if the license was input with `.0.0`
		if zero.Match([]byte(id)) {
			idBytes = zero.ReplaceAll([]byte(id), []byte("${2}${3}"))
		} else {
			idBytes = noZero.ReplaceAll([]byte(id), []byte("${1}${2}.0${3}"))
		}

		value, exists = licenseIDs[string(idBytes)]
	}
	return value, exists
}

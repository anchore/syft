package spdxlicense

import (
	"strings"
)

// https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-short-name
// If a license generated in license_list.go is not found when looking up by ID,
// then the ID function will check this map for short name exceptions as detailed
// in the above link.
var licenseShortNameExceptions = map[string]string{
	"gpl":    "GPL-1.0",
	"gpl-1":  "GPL-1.0",
	"gpl-2":  "GPL-2.0",
	"gpl-3":  "GPL-3.0",
	"lgpl-2": "LGPL-2.0",
	"lgpl-3": "LGPL-3.0",
}

//go:generate go run generate_license_list.go

func ID(id string) (string, bool) {
	id = strings.ToLower(id)
	// check if id can be found from open source license registry
	if value, exists := licenseIDs[id]; exists {
		return value, exists
	}

	// check known license short name exceptions
	value, exits := licenseShortNameExceptions[id]
	return value, exits
}

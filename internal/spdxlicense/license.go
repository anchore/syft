package spdxlicense

import (
	"strings"
)

var debianLicenseLabels = map[string]string{
	"Artistic": "Artistic-1.0-Perl",
	"BSD":      "BSD-1-Clause",
	"GPL":      "GPL-1.0",
	"GPL-1":    "GPL-1.0",
	"GPL-2":    "GPL-2.0",
	"GPL-3":    "GPL-3.0",
	"LGPL-2":   "LGPL-2.0",
	"LGPL-3":   "LGPL-3.0",
}

//go:generate go run generate_license_list.go

func ID(id string) (string, bool) {
	value, exists := licenseIDs[strings.ToLower(id)]
	return value, exists
}

func DebianID(id string) (string, bool) {
	value, exists := debianLicenseLabels[strings.ToLower(id)]
	return value, exists
}

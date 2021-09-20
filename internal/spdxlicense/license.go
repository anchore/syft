package spdxlicense

import (
	"strings"
)

var debianLicenseLabels = map[string]string{
	"artistic": "Artistic-1.0-Perl",
	"bsd":      "BSD-1-Clause",
	"gpl":      "GPL-1.0",
	"gpl-1":    "GPL-1.0",
	"gpl-2":    "GPL-2.0",
	"gpl-3":    "GPL-3.0",
	"lgpl-2":   "LGPL-2.0",
	"lgpl-3":   "LGPL-3.0",
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

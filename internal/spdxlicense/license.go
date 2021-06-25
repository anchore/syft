package spdxlicense

import (
	"strings"
)

//go:generate go run generate_license_list.go

func ID(id string) (string, bool) {
	value, exists := licenseIDs[strings.ToLower(id)]
	return value, exists
}

package spdxutil

import (
	"github.com/anchore/syft/syft/sbom"
)

const DefaultVersion = "2.3"

const (
	JSONFormatID     sbom.FormatID = "spdx-json"
	TagValueFormatID sbom.FormatID = "spdx-tag-value"
)

func SupportedVersions(id sbom.FormatID) []string {
	versions := []string{
		"2.2",
		"2.3",
	}

	if id != JSONFormatID {
		// JSON format is not supported in v2.1
		return append([]string{"2.1"}, versions...)
	}

	return versions
}

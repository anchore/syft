package spdxutil

import (
	"github.com/anchore/syft/syft/sbom"
)

const (
	DefaultVersion = "2.3"
	V3_0_1         = "3.0.1"

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
		versions = append([]string{"2.1"}, versions...)
	} else {
		// is JSON, v3 only supported in JSON format:
		versions = append(versions, V3_0_1)
	}

	return versions
}

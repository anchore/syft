package cyclonedxutil

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/sbom"
)

const (
	XMLFormatID  sbom.FormatID = "cyclonedx-xml"
	JSONFormatID sbom.FormatID = "cyclonedx-json"
)

func SupportedVersions(id sbom.FormatID) []string {
	versions := []string{
		"1.2",
		"1.3",
		"1.4",
		"1.5",
	}

	if id != JSONFormatID {
		// JSON format not supported for version < 1.2
		versions = append([]string{"1.0", "1.1"}, versions...)
	}

	return versions
}

func SpecVersionFromString(v string) (cyclonedx.SpecVersion, error) {
	switch v {
	case "1.0":
		return cyclonedx.SpecVersion1_0, nil
	case "1.1":
		return cyclonedx.SpecVersion1_1, nil
	case "1.2":
		return cyclonedx.SpecVersion1_2, nil
	case "1.3":
		return cyclonedx.SpecVersion1_3, nil
	case "1.4":
		return cyclonedx.SpecVersion1_4, nil
	case "1.5":
		return cyclonedx.SpecVersion1_5, nil
	}
	return -1, fmt.Errorf("unsupported CycloneDX version %q", v)
}

func VersionFromSpecVersion(spec cyclonedx.SpecVersion) string {
	switch spec {
	case cyclonedx.SpecVersion1_0:
		return "1.0"
	case cyclonedx.SpecVersion1_1:
		return "1.1"
	case cyclonedx.SpecVersion1_2:
		return "1.2"
	case cyclonedx.SpecVersion1_3:
		return "1.3"
	case cyclonedx.SpecVersion1_4:
		return "1.4"
	case cyclonedx.SpecVersion1_5:
		return "1.5"
	}
	return ""
}

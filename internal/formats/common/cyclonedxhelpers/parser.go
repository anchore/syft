package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/sbom"
)

func GetParser() sbom.Parser {
	return func(input interface{}) (*sbom.SBOM, error) {
		switch input := input.(type) {
		case *cyclonedx.BOM:
			return toSyftModel(input)
		default:
			return nil, sbom.ErrParsingNotSupported
		}
	}
}

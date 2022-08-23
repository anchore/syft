package spdxhelpers

import (
	"github.com/anchore/syft/syft/sbom"
	"github.com/spdx/tools-golang/spdx"
)

func GetParser() sbom.Parser {
	return func(input interface{}) (*sbom.SBOM, error) {
		switch input := input.(type) {
		case *spdx.Document2_2:
			return ToSyftModel(input)
		default:
			return nil, sbom.ErrParsingNotSupported
		}
	}
}

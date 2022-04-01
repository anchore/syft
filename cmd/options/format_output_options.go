package options

import (
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
)

// returns list of formatted syft outputs
func formatSyftOutputs(ids ...sbom.FormatID) (outputs []string) {
	for _, id := range ids {
		switch id {
		case syft.JSONFormatID:
			outputs = append(outputs, "syft-json")
		case syft.TextFormatID:
			outputs = append(outputs, "text")
		case syft.TableFormatID:
			outputs = append(outputs, "table")
		case syft.SPDXJSONFormatID:
			outputs = append(outputs, "spdx-json")
		case syft.SPDXTagValueFormatID:
			outputs = append(outputs, "spdx-tag-value")
		case syft.CycloneDxXMLFormatID:
			outputs = append(outputs, "cyclonedx-xml")
		case syft.CycloneDxJSONFormatID:
			outputs = append(outputs, "cyclonedx-json")
		case syft.GitHubID:
			outputs = append(outputs, "github", "github-json")
		default:
			outputs = append(outputs, string(id))
		}
	}
	return outputs
}

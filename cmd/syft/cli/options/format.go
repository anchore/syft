package options

import (
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
)

func FormatAliases(ids ...sbom.FormatID) (aliases []string) {
	for _, id := range ids {
		switch id {
		case syft.JSONFormatID:
			aliases = append(aliases, "syft-json")
		case syft.TextFormatID:
			aliases = append(aliases, "text")
		case syft.TableFormatID:
			aliases = append(aliases, "table")
		case syft.SPDXJSONFormatID:
			aliases = append(aliases, "spdx-json")
		case syft.SPDXTagValueFormatID:
			aliases = append(aliases, "spdx-tag-value")
		case syft.CycloneDxXMLFormatID:
			aliases = append(aliases, "cyclonedx-xml")
		case syft.CycloneDxJSONFormatID:
			aliases = append(aliases, "cyclonedx-json")
		case syft.GitHubID:
			aliases = append(aliases, "github", "github-json")
		default:
			aliases = append(aliases, string(id))
		}
	}
	return aliases
}

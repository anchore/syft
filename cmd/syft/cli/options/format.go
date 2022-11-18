package options

import (
	"github.com/anchore/syft/syft/formats/cyclonedxjson"
	"github.com/anchore/syft/syft/formats/cyclonedxxml"
	"github.com/anchore/syft/syft/formats/github"
	"github.com/anchore/syft/syft/formats/spdxjson"
	"github.com/anchore/syft/syft/formats/spdxtagvalue"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/formats/text"
	"github.com/anchore/syft/syft/sbom"
)

func FormatAliases(ids ...sbom.FormatID) (aliases []string) {
	for _, id := range ids {
		switch id {
		case syftjson.ID:
			aliases = append(aliases, "syft-json")
		case text.ID:
			aliases = append(aliases, "text")
		case table.ID:
			aliases = append(aliases, "table")
		case spdxjson.ID:
			aliases = append(aliases, "spdx-json")
		case spdxtagvalue.ID:
			aliases = append(aliases, "spdx-tag-value")
		case cyclonedxxml.ID:
			aliases = append(aliases, "cyclonedx-xml")
		case cyclonedxjson.ID:
			aliases = append(aliases, "cyclonedx-json")
		case github.ID:
			aliases = append(aliases, "github", "github-json")
		default:
			aliases = append(aliases, string(id))
		}
	}
	return aliases
}

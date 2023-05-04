package github

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "github-json"

func Format() sbom.Format {
	return sbom.NewFormat(
		sbom.AnyVersion,
		func(writer io.Writer, sbom sbom.SBOM) error {
			bom := toGithubModel(&sbom)

			encoder := json.NewEncoder(writer)
			encoder.SetEscapeHTML(false)
			encoder.SetIndent("", "  ")

			return encoder.Encode(bom)
		},
		nil,
		nil,
		ID, "github",
	)
}

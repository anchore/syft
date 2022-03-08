package github

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "github-1-json"

func Format() sbom.Format {
	return sbom.NewFormat(
		ID,
		func(writer io.Writer, sbom sbom.SBOM) error {
			bom := toGithubModel(&sbom)

			// bytes, err := json.Marshal(bom)
			bytes, err := json.MarshalIndent(bom, "", "  ")
			if err != nil {
				return err
			}
			_, err = writer.Write(bytes)

			return err
		},
		nil,
		nil,
	)
}

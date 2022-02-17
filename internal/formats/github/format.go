package github

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
)

func Format() format.Format {
	return format.NewFormat(
		format.GitHubJSON,
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

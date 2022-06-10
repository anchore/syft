package markdown

import (
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "markdown"

func Format() sbom.Format {
	return sbom.NewFormat(
		ID,
		encoder,
		nil,
		nil,
	)
}

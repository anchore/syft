package text

import (
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "syft-text"

func Format() sbom.Format {
	return sbom.NewFormat(
		ID,
		encoder,
		nil,
		nil,
	)
}

package syftjson

import (
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "syft-4-json"

func Format() sbom.Format {
	return sbom.NewFormat(
		ID,
		encoder,
		decoder,
		validator,
	)
}

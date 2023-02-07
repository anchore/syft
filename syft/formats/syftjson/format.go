package syftjson

import (
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "syft-json"

func Format() sbom.Format {
	return sbom.NewFormat(
		"6",
		encoder,
		decoder,
		validator,
		ID, "json", "syft",
	)
}

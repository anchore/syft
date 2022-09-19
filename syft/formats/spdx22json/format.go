package spdx22json

import (
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "spdx-2-json"

// note: this format is LOSSY relative to the syftjson format
func Format() sbom.Format {
	return sbom.NewFormat(
		ID,
		encoder,
		decoder,
		validator,
	)
}

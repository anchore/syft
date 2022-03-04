package spdx22tagvalue

import (
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "spdx-2-tag-value"

// note: this format is LOSSY relative to the syftjson formation, which means that decoding and validation is not supported at this time
func Format() sbom.Format {
	return sbom.NewFormat(
		ID,
		encoder,
		decoder,
		validator,
	)
}

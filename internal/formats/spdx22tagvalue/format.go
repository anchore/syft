package spdx22tagvalue

import (
	"github.com/anchore/syft/syft/sbom"
)

// note: this format is LOSSY relative to the syftjson formation, which means that decoding and validation is not supported at this time
func Format(names ...string) sbom.Format {
	return sbom.NewFormat(
		encoder,
		decoder,
		validator,
		append(names, "spdx-tag-value", "spdx-tv", "spdx")...,
	)
}

package spdx22json

import (
	"github.com/anchore/syft/syft/sbom"
)

// note: this format is LOSSY relative to the syftjson format
func Format(names ...string) sbom.Format {
	return sbom.NewFormat(
		encoder,
		decoder,
		validator,
		append(names, "spdx-json", "spdx")...,
	)
}

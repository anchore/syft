package spdxjson

import (
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "spdx-json"

var IDs = []sbom.FormatID{ID}

// note: this format is LOSSY relative to the syftjson format

func Format2_2() sbom.Format {
	return sbom.NewFormat(
		"2.2",
		encoder2_2,
		decoder,
		validator,
		IDs...,
	)
}

func Format2_3() sbom.Format {
	return sbom.NewFormat(
		"2.3",
		encoder2_3,
		decoder,
		validator,
		IDs...,
	)
}

var Format = Format2_3

package spdx22json

import "github.com/anchore/syft/syft/format"

// note: this format is LOSSY relative to the syftjson formation, which means that decoding and validation is not supported at this time
func Format() format.Format {
	return format.NewFormat(
		format.SPDXJSONOption,
		encoder,
		nil,
		nil,
	)
}

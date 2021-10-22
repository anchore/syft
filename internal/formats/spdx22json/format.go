package spdx22json

import "github.com/anchore/syft/syft/format"

// note: this format is LOSSY relative to the syftjson formation, which means that decoding may not provide full syft native models
func Format() format.Format {
	return format.NewFormat(
		format.SPDXJSONOption,
		encoder,
		decoder,
		validator,
	)
}

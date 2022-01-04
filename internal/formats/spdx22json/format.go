package spdx22json

import "github.com/anchore/syft/syft/format"

// note: this format is LOSSY relative to the syftjson format
func Format() format.Format {
	return format.NewFormat(
		format.SPDXJSONOption,
		encoder,
		decoder,
		validator,
	)
}

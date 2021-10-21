package spdx22json

import "github.com/anchore/syft/syft/format"

func Format() format.Format {
	return format.NewFormat(
		format.SPDXJSONOption,
		encoder,
		decoder,
		validator,
	)
}

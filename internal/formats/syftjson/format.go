package syftjson

import "github.com/anchore/syft/syft/format"

func Format() format.Format {
	return format.NewFormat(
		format.JSONOption,
		encoder,
		decoder,
		validator,
	)
}

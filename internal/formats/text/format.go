package text

import "github.com/anchore/syft/syft/format"

func Format() format.Format {
	return format.NewFormat(
		format.TextOption,
		encoder,
		nil,
		nil,
	)
}

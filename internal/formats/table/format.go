package table

import "github.com/anchore/syft/syft/format"

func Format() format.Format {
	return format.NewFormat(
		format.TableOption,
		encoder,
		nil,
		nil,
	)
}

package cyclonedx

import "github.com/anchore/syft/syft/format"

func Format() format.Format {
	return format.NewFormat(
		format.CycloneDxOption,
		encoder,
		nil,
		nil,
	)
}

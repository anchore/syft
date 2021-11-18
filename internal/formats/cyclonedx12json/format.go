package cyclonedx12json

import "github.com/anchore/syft/syft/format"

func Format() format.Format {
	return format.NewFormat(
		format.CycloneDxJSONOption,
		encoder,
		nil,
		nil,
	)
}

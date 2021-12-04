package cyclonedx13xml

import "github.com/anchore/syft/syft/format"

func Format() format.Format {
	return format.NewFormat(
		format.CycloneDxXMLOption,
		encoder,
		nil,
		nil,
	)
}

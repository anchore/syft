package cyclonedx13xml

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/internal/formats/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format"
)

func Format() format.Format {
	return format.NewFormat(
		format.CycloneDxXMLOption,
		encoder,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatXML),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatXML),
	)
}

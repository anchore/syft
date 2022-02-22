package cyclonedx13json

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/internal/formats/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format"
)

func Format() format.Format {
	return format.NewFormat(
		format.CycloneDxJSONOption,
		encoder,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatJSON),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatJSON),
	)
}

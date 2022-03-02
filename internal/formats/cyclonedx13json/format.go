package cyclonedx13json

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/internal/formats/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func Format(names ...string) sbom.Format {
	return sbom.NewFormat(
		encoder,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatJSON),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatJSON),
		append(names, "cyclonedx-json", "cyclone-json", "cyclonedx")...,
	)
}

package cyclonedx13xml

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/internal/formats/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func Format(names ...string) sbom.Format {
	return sbom.NewFormat(
		encoder,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatXML),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatXML),
		append(names, "cyclonedx-xml", "cyclone-xml", "cyclonedx")...,
	)
}

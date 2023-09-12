package cyclonedxjson

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/formats/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "cyclonedx-json"

var Format = Format1_4

func Format1_0() sbom.Format {
	return sbom.NewFormat(
		cyclonedx.SpecVersion1_0.String(),
		encoderV1_0,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatJSON),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatJSON),
		ID,
	)
}

func Format1_1() sbom.Format {
	return sbom.NewFormat(
		cyclonedx.SpecVersion1_1.String(),
		encoderV1_1,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatJSON),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatJSON),
		ID,
	)
}

func Format1_2() sbom.Format {
	return sbom.NewFormat(
		cyclonedx.SpecVersion1_2.String(),
		encoderV1_2,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatJSON),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatJSON),
		ID,
	)
}

func Format1_3() sbom.Format {
	return sbom.NewFormat(
		cyclonedx.SpecVersion1_3.String(),
		encoderV1_3,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatJSON),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatJSON),
		ID,
	)
}

func Format1_4() sbom.Format {
	return sbom.NewFormat(
		cyclonedx.SpecVersion1_4.String(),
		encoderV1_4,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatJSON),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatJSON),
		ID,
	)
}

func Format1_5() sbom.Format {
	return sbom.NewFormat(
		cyclonedx.SpecVersion1_5.String(),
		encoderV1_5,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatJSON),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatJSON),
		ID,
	)
}

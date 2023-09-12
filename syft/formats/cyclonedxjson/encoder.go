package cyclonedxjson

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/formats/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func encoder_v1_0(output io.Writer, s sbom.SBOM) error {
	enc, bom := buildEncoder(output, s)
	return enc.EncodeVersion(bom, cyclonedx.SpecVersion1_0)
}

func encoder_v1_1(output io.Writer, s sbom.SBOM) error {
	enc, bom := buildEncoder(output, s)
	return enc.EncodeVersion(bom, cyclonedx.SpecVersion1_1)
}

func encoder_v1_2(output io.Writer, s sbom.SBOM) error {
	enc, bom := buildEncoder(output, s)
	return enc.EncodeVersion(bom, cyclonedx.SpecVersion1_2)
}

func encoder_v1_3(output io.Writer, s sbom.SBOM) error {
	enc, bom := buildEncoder(output, s)
	return enc.EncodeVersion(bom, cyclonedx.SpecVersion1_3)
}

func encoder_v1_4(output io.Writer, s sbom.SBOM) error {
	enc, bom := buildEncoder(output, s)
	return enc.EncodeVersion(bom, cyclonedx.SpecVersion1_4)
}

func encoder_v1_5(output io.Writer, s sbom.SBOM) error {
	enc, bom := buildEncoder(output, s)
	return enc.EncodeVersion(bom, cyclonedx.SpecVersion1_5)
}

func buildEncoder(output io.Writer, s sbom.SBOM) (cyclonedx.BOMEncoder, *cyclonedx.BOM) {
	bom := cyclonedxhelpers.ToFormatModel(s)
	enc := cyclonedx.NewBOMEncoder(output, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	enc.SetEscapeHTML(false)
	return enc, bom
}

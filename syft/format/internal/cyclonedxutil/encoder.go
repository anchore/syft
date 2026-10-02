package cyclonedxutil

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

type Encoder struct {
	version cyclonedx.SpecVersion
	format  cyclonedx.BOMFileFormat
	pretty  bool
}

func NewEncoder(version string, format cyclonedx.BOMFileFormat, pretty bool) (Encoder, error) {
	specVersion, err := SpecVersionFromString(version)
	if err != nil {
		return Encoder{}, err
	}
	return Encoder{
		version: specVersion,
		format:  format,
		pretty:  pretty,
	}, nil
}

func (e Encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	bom := cyclonedxhelpers.ToFormatModel(s)
	if e.version < cyclonedx.SpecVersion1_6 && bom.Components != nil {
		components := (*bom.Components)[:0]
		for _, component := range *bom.Components {
			if component.Type != cyclonedx.ComponentTypeCryptographicAsset {
				components = append(components, component)
			}
		}
		bom.Components = &components
	}
	enc := cyclonedx.NewBOMEncoder(writer, e.format)
	enc.SetPretty(e.pretty)
	enc.SetEscapeHTML(false)

	return enc.EncodeVersion(bom, e.version)
}

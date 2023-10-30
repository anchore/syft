package cyclonedxutil

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

const DefaultVersion = "1.5"

type Encoder struct {
	version cyclonedx.SpecVersion
	format  cyclonedx.BOMFileFormat
}

func NewEncoder(version string, format cyclonedx.BOMFileFormat) (Encoder, error) {
	specVersion, err := SpecVersionFromString(version)
	if err != nil {
		return Encoder{}, err
	}
	return Encoder{
		version: specVersion,
		format:  format,
	}, nil
}

func (e Encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	bom := cyclonedxhelpers.ToFormatModel(s)
	enc := cyclonedx.NewBOMEncoder(writer, e.format)
	enc.SetPretty(true)
	enc.SetEscapeHTML(false)

	return enc.EncodeVersion(bom, e.version)
}

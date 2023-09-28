package cyclonedxutil

import (
	"fmt"
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

func SpecVersionFromString(v string) (cyclonedx.SpecVersion, error) {
	switch v {
	case "1.0":
		return cyclonedx.SpecVersion1_0, nil
	case "1.1":
		return cyclonedx.SpecVersion1_1, nil
	case "1.2":
		return cyclonedx.SpecVersion1_2, nil
	case "1.3":
		return cyclonedx.SpecVersion1_3, nil
	case "1.4":
		return cyclonedx.SpecVersion1_4, nil
	case "1.5", "", "1", "1.x":
		return cyclonedx.SpecVersion1_5, nil
	}
	return -1, fmt.Errorf("unsupported CycloneDX version %q", v)
}

func VersionFromSpecVersion(spec cyclonedx.SpecVersion) string {
	switch spec {
	case cyclonedx.SpecVersion1_0:
		return "1.0"
	case cyclonedx.SpecVersion1_1:
		return "1.1"
	case cyclonedx.SpecVersion1_2:
		return "1.2"
	case cyclonedx.SpecVersion1_3:
		return "1.3"
	case cyclonedx.SpecVersion1_4:
		return "1.4"
	case cyclonedx.SpecVersion1_5:
		return "1.5"
	}
	return ""
}

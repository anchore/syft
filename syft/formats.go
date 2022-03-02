package syft

import (
	"bytes"

	"github.com/anchore/syft/internal/formats/cyclonedx13json"
	"github.com/anchore/syft/internal/formats/cyclonedx13xml"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/spdx22tagvalue"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/internal/formats/text"
	"github.com/anchore/syft/syft/sbom"
)

const (
	JSONFormatOption          FormatOption = "json"
	TextFormatOption          FormatOption = "text"
	TableFormatOption         FormatOption = "table"
	CycloneDxXMLFormatOption  FormatOption = "cyclonedx-xml"
	CycloneDxJSONFormatOption FormatOption = "cyclonedx-json"
	SPDXTagValueFormatOption  FormatOption = "spdx-tag-value"
	SPDXJSONFormatOption      FormatOption = "spdx-json"
)

var formats []sbom.Format

func init() {
	formats = []sbom.Format{
		syftjson.Format(string(JSONFormatOption)),
		cyclonedx13xml.Format(string(CycloneDxXMLFormatOption)),
		cyclonedx13json.Format(string(CycloneDxJSONFormatOption)),
		spdx22tagvalue.Format(string(SPDXTagValueFormatOption)),
		spdx22json.Format(string(SPDXJSONFormatOption)),
		table.Format(string(TableFormatOption)),
		text.Format(string(TextFormatOption)),
	}
}

type FormatOption string

func FormatOptions() []FormatOption {
	return []FormatOption{
		JSONFormatOption,
		TextFormatOption,
		TableFormatOption,
		CycloneDxXMLFormatOption,
		CycloneDxJSONFormatOption,
		SPDXTagValueFormatOption,
		SPDXJSONFormatOption,
	}
}

func FormatByOption(option FormatOption) sbom.Format {
	return FormatByName(string(option))
}

func FormatByName(name string) sbom.Format {
	for _, f := range formats {
		for _, formatName := range f.Names() {
			if formatName == name {
				return f
			}
		}
	}
	return nil
}

func IdentifyFormat(by []byte) sbom.Format {
	for _, f := range formats {
		if err := f.Validate(bytes.NewReader(by)); err != nil {
			continue
		}
		return f
	}
	return nil
}

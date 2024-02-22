package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/sbom"
)

var _ clio.PostLoader = (*Format)(nil)

// Format contains all user configuration for output formatting.
type Format struct {
	Pretty        *bool               `yaml:"pretty" json:"pretty" mapstructure:"pretty"`
	Template      FormatTemplate      `yaml:"template" json:"template" mapstructure:"template"`
	SyftJSON      FormatSyftJSON      `yaml:"json" json:"json" mapstructure:"json"`
	SPDXJSON      FormatSPDXJSON      `yaml:"spdx-json" json:"spdx-json" mapstructure:"spdx-json"`
	CyclonedxJSON FormatCyclonedxJSON `yaml:"cyclonedx-json" json:"cyclonedx-json" mapstructure:"cyclonedx-json"`
	CyclonedxXML  FormatCyclonedxXML  `yaml:"cyclonedx-xml" json:"cyclonedx-xml" mapstructure:"cyclonedx-xml"`
}

func (o *Format) PostLoad() error {
	o.SyftJSON.Pretty = multiLevelOption[bool](false, o.Pretty, o.SyftJSON.Pretty)
	o.SPDXJSON.Pretty = multiLevelOption[bool](false, o.Pretty, o.SPDXJSON.Pretty)
	o.CyclonedxJSON.Pretty = multiLevelOption[bool](false, o.Pretty, o.CyclonedxJSON.Pretty)
	o.CyclonedxXML.Pretty = multiLevelOption[bool](false, o.Pretty, o.CyclonedxXML.Pretty)

	return nil
}

func DefaultFormat() Format {
	return Format{
		Template:      DefaultFormatTemplate(),
		SyftJSON:      DefaultFormatJSON(),
		SPDXJSON:      DefaultFormatSPDXJSON(),
		CyclonedxJSON: DefaultFormatCyclonedxJSON(),
		CyclonedxXML:  DefaultFormatCyclonedxXML(),
	}
}

func (o Format) Encoders() ([]sbom.FormatEncoder, error) {
	return format.EncodersConfig{
		Template:      o.Template.config(),
		SyftJSON:      o.SyftJSON.config(),
		SPDXJSON:      o.SPDXJSON.config(format.AllVersions),                   // we support multiple versions, not just a single version
		SPDXTagValue:  spdxtagvalue.EncoderConfig{Version: format.AllVersions}, // we support multiple versions, not just a single version
		CyclonedxJSON: o.CyclonedxJSON.config(format.AllVersions),              // we support multiple versions, not just a single version
		CyclonedxXML:  o.CyclonedxXML.config(format.AllVersions),               // we support multiple versions, not just a single version
	}.Encoders()
}

func multiLevelOption[T any](defaultValue T, option ...*T) *T {
	result := defaultValue
	for _, opt := range option {
		if opt != nil {
			result = *opt
		}
	}
	return &result
}

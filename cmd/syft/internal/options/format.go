package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/sbom"
)

var _ interface {
	clio.PostLoader
	clio.FieldDescriber
} = (*Format)(nil)

// Format contains all user configuration for output formatting.
type Format struct {
	Pretty        *bool               `yaml:"pretty" json:"pretty" mapstructure:"pretty"`
	Template      FormatTemplate      `yaml:"template" json:"template" mapstructure:"template" description:"all template format options"`
	SyftJSON      FormatSyftJSON      `yaml:"json" json:"json" mapstructure:"json" description:"all syft-json format options"`
	SPDXJSON      FormatSPDXJSON      `yaml:"spdx-json" json:"spdx-json" mapstructure:"spdx-json" description:"all spdx-json format options"`
	CyclonedxJSON FormatCyclonedxJSON `yaml:"cyclonedx-json" json:"cyclonedx-json" mapstructure:"cyclonedx-json" description:"all cyclonedx-json format options"`
	CyclonedxXML  FormatCyclonedxXML  `yaml:"cyclonedx-xml" json:"cyclonedx-xml" mapstructure:"cyclonedx-xml" description:"all cyclonedx-xml format options"`
}

func (o *Format) PostLoad() error {
	o.SyftJSON.Pretty = multiLevelOption[bool](false, o.Pretty, o.SyftJSON.Pretty)
	o.SPDXJSON.Pretty = multiLevelOption[bool](false, o.Pretty, o.SPDXJSON.Pretty)
	o.CyclonedxJSON.Pretty = multiLevelOption[bool](false, o.Pretty, o.CyclonedxJSON.Pretty)
	o.CyclonedxXML.Pretty = multiLevelOption[bool](false, o.Pretty, o.CyclonedxXML.Pretty)

	return nil
}

func (o *Format) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.Pretty, `default value for all formats that support the "pretty" option (default is unset)`)
	descriptions.Add(&o.SyftJSON, `all syft-json format options`)
	descriptions.Add(&o.SyftJSON.Legacy, `transform any syft-json output to conform to an approximation of the v11.0.1 schema. This includes:
- using the package metadata type names from before v12 of the JSON schema (changed in https://github.com/anchore/syft/pull/1983)

Note: this will still include package types and fields that were added at or after json schema v12. This means
that output might not strictly be json schema v11 compliant, however, for consumers that require time to port
over to the final syft 1.0 json output this option can be used to ease the transition.

Note: long term support for this option is not guaranteed (it may change or break at any time)`)

	descriptions.Add(&o.Template.Path, `path to the template file to use when rendering the output with the template output format. 
Note that all template paths are based on the current syft-json schema`)
	descriptions.Add(&o.Template.Legacy, `if true, uses the go structs for the syft-json format for templating. 
if false, uses the syft-json output for templating (which follows the syft JSON schema exactly).

Note: long term support for this option is not guaranteed (it may change or break at any time)`)

	prettyDescription := `include space indentation and newlines
note: inherits default value from 'format.pretty' or 'false' if parent is unset`
	descriptions.Add(&o.SyftJSON.Pretty, prettyDescription)
	descriptions.Add(&o.SPDXJSON.Pretty, prettyDescription)
	descriptions.Add(&o.CyclonedxJSON.Pretty, prettyDescription)
	descriptions.Add(&o.CyclonedxXML.Pretty, prettyDescription)
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

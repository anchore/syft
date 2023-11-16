package options

import (
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/github"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/table"
	"github.com/anchore/syft/syft/format/template"
	"github.com/anchore/syft/syft/format/text"
	"github.com/anchore/syft/syft/sbom"
)

// Format contains all user configuration for output formatting.
type Format struct {
	Template FormatTemplate `yaml:"template" json:"template" mapstructure:"template"`
	JSON     FormatJSON     `yaml:"json" json:"json" mapstructure:"json"`
}

func DefaultFormat() Format {
	return Format{
		Template: DefaultFormatTemplate(),
		JSON:     DefaultFormatJSON(),
	}
}

func (o *Format) Encoders() ([]sbom.FormatEncoder, error) {
	// setup all encoders based on the configuration
	var list encoderList

	// in the future there will be application configuration options that can be used to set the default output format
	list.addWithErr(template.ID)(o.Template.formatEncoders())
	list.addWithErr(syftjson.ID)(o.JSON.formatEncoders())
	list.add(table.ID)(table.NewFormatEncoder())
	list.add(text.ID)(text.NewFormatEncoder())
	list.add(github.ID)(github.NewFormatEncoder())
	list.addWithErr(cyclonedxxml.ID)(cycloneDxXMLEncoders())
	list.addWithErr(cyclonedxjson.ID)(cycloneDxJSONEncoders())
	list.addWithErr(spdxjson.ID)(spdxJSONEncoders())
	list.addWithErr(spdxtagvalue.ID)(spdxTagValueEncoders())

	return list.encoders, list.err
}

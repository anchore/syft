package options

import (
	"fmt"

	"github.com/hashicorp/go-multierror"

	"github.com/anchore/clio"
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

func (o *Format) Encoders() ([]sbom.FormatEncoder, error) {
	// setup all encoders based on the configuration
	var list encoderList

	// in the future there will be application configuration options that can be used to set the default output format
	list.addWithErr(template.ID)(o.Template.formatEncoders())
	list.addWithErr(syftjson.ID)(o.SyftJSON.formatEncoders())
	list.add(table.ID)(table.NewFormatEncoder())
	list.add(text.ID)(text.NewFormatEncoder())
	list.add(github.ID)(github.NewFormatEncoder())
	list.addWithErr(cyclonedxxml.ID)(o.CyclonedxXML.formatEncoders())
	list.addWithErr(cyclonedxjson.ID)(o.CyclonedxJSON.formatEncoders())
	list.addWithErr(spdxjson.ID)(o.SPDXJSON.formatEncoders())
	list.addWithErr(spdxtagvalue.ID)(spdxTagValueEncoders())

	return list.encoders, list.err
}

// TODO: when application configuration is made for this format then this should be ported to the options object
// that is created for that configuration (as done with the template output option)
func spdxTagValueEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)
	for _, v := range spdxtagvalue.SupportedVersions() {
		enc, err := spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.EncoderConfig{Version: v})
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

type encoderList struct {
	encoders []sbom.FormatEncoder
	err      error
}

func (l *encoderList) addWithErr(name sbom.FormatID) func([]sbom.FormatEncoder, error) {
	return func(encs []sbom.FormatEncoder, err error) {
		if err != nil {
			l.err = multierror.Append(l.err, fmt.Errorf("unable to configure %q format encoder: %w", name, err))
			return
		}
		for _, enc := range encs {
			if enc == nil {
				l.err = multierror.Append(l.err, fmt.Errorf("unable to configure %q format encoder: nil encoder returned", name))
				continue
			}
			l.encoders = append(l.encoders, enc)
		}
	}
}

func (l *encoderList) add(name sbom.FormatID) func(...sbom.FormatEncoder) {
	return func(encs ...sbom.FormatEncoder) {
		for _, enc := range encs {
			if enc == nil {
				l.err = multierror.Append(l.err, fmt.Errorf("unable to configure %q format encoder: nil encoder returned", name))
				continue
			}
			l.encoders = append(l.encoders, enc)
		}
	}
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

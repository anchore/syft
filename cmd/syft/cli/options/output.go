package options

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/format"
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

var _ interface {
	clio.FlagAdder
	clio.PostLoader
} = (*Output)(nil)

// Output has the standard output options syft accepts: multiple -o, --file, --template
type Output struct {
	AllowableOptions     []string `yaml:"-" json:"-" mapstructure:"-"`
	AllowMultipleOutputs bool     `yaml:"-" json:"-" mapstructure:"-"`
	Outputs              []string `yaml:"output" json:"output" mapstructure:"output"` // -o, the format to use for output
	OutputFile           `yaml:",inline" json:"" mapstructure:",squash"`
	OutputTemplate       `yaml:"template" json:"template" mapstructure:"template"`

	// populated after configuration is loaded
	encoders []sbom.FormatEncoder
}

func DefaultOutput() Output {
	return Output{
		AllowMultipleOutputs: true,
		Outputs:              []string{string(table.ID)},
	}
}

func (o *Output) AddFlags(flags clio.FlagSet) {
	encs := format.DefaultEncoders()
	var names []string
	for _, e := range encs {
		names = append(names, e.ID().String())
	}
	sort.Strings(names)

	flags.StringArrayVarP(&o.Outputs, "output", "o",
		fmt.Sprintf("report output format, options=%v", names))
}

func (o *Output) PostLoad() error {
	// setup all encoders based on the configuration
	var list encoderList

	// in the future there will be application configuration options that can be used to set the default output format
	list.attempt(template.ID)(o.OutputTemplate.formatEncoders())
	list.add(syftjson.ID)(syftjson.DefaultFormatEncoder())
	list.add(table.ID)(table.DefaultFormatEncoder())
	list.add(text.ID)(text.DefaultFormatEncoder())
	list.add(github.ID)(github.DefaultFormatEncoder())
	list.attempt(cyclonedxxml.ID)(cycloneDxXMLEncoders())
	list.attempt(cyclonedxjson.ID)(cycloneDxJSONEncoders())
	list.attempt(spdxjson.ID)(spdxJSONEncoders())
	list.attempt(spdxtagvalue.ID)(spdxTagValueEncoders())

	o.encoders = list.encoders

	return list.err
}

// TODO: when application configuration is made for this format then this should be ported to the options object
// that is created for that configuration (as done with the template output option)
func cycloneDxXMLEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)
	for _, v := range cyclonedxxml.SupportedVersions() {
		enc, err := cyclonedxxml.NewFormatEncoder(cyclonedxxml.EncoderConfig{Version: v})
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

// TODO: when application configuration is made for this format then this should be ported to the options object
// that is created for that configuration (as done with the template output option)
func cycloneDxJSONEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)
	for _, v := range cyclonedxjson.SupportedVersions() {
		enc, err := cyclonedxjson.NewFormatEncoder(cyclonedxjson.EncoderConfig{Version: v})
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

// TODO: when application configuration is made for this format then this should be ported to the options object
// that is created for that configuration (as done with the template output option)
func spdxJSONEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)
	for _, v := range spdxjson.SupportedVersions() {
		enc, err := spdxjson.NewFormatEncoder(spdxjson.EncoderConfig{Version: v})
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

// TODO: when application configuration is made for this format then this should be ported to the options object
// that is created for that configuration (as done with the template output option)
func spdxTagValueEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)
	for _, v := range spdxtagvalue.SupportedVersions() {
		enc, err := spdxtagvalue.NewFormatEncoder(spdxtagvalue.EncoderConfig{Version: v})
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

func (o Output) SBOMWriter() (sbom.Writer, error) {
	names := o.OutputNameSet()

	if len(o.Outputs) > 1 && !o.AllowMultipleOutputs {
		return nil, fmt.Errorf("only one output format is allowed (given %d: %s)", len(o.Outputs), names)
	}

	usesTemplateOutput := names.Has(string(template.ID))

	if usesTemplateOutput && o.OutputTemplate.Path == "" {
		return nil, fmt.Errorf(`must specify path to template file when using "template" output format`)
	}

	return makeSBOMWriter(o.Outputs, o.File, o.encoders)
}

func (o Output) OutputNameSet() *strset.Set {
	names := strset.New()
	for _, output := range o.Outputs {
		fields := strings.Split(output, "=")
		names.Add(fields[0])
	}

	return names
}

type encoderList struct {
	encoders []sbom.FormatEncoder
	err      error
}

func (l *encoderList) attempt(name sbom.FormatID) func([]sbom.FormatEncoder, error) {
	return func(encs []sbom.FormatEncoder, err error) {
		for _, enc := range encs {
			if err != nil {
				l.err = multierror.Append(l.err, fmt.Errorf("unable to configure %q format encoder: %w", name, err))
				return
			}
			if enc == nil {
				l.err = multierror.Append(l.err, fmt.Errorf("unable to configure %q format encoder: nil encoder returned", name))
				return
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
				return
			}
			l.encoders = append(l.encoders, enc)
		}
	}
}

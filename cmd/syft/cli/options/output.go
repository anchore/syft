package options

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/scylladb/go-set/strset"

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
}

func DefaultOutput() Output {
	return Output{
		AllowMultipleOutputs: true,
		Outputs:              []string{string(table.ID)},
		OutputFile: OutputFile{
			Enabled: true,
		},
		OutputTemplate: OutputTemplate{
			Enabled: true,
		},
	}
}

func (o *Output) AddFlags(flags clio.FlagSet) {
	var names []string
	for _, id := range supportedIDs() {
		names = append(names, id.String())
	}
	sort.Strings(names)

	flags.StringArrayVarP(&o.Outputs, "output", "o",
		fmt.Sprintf("report output format (<format>=<file> to output to a file), formats=%v", names))
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

	encoders, err := o.Encoders()
	if err != nil {
		return nil, err
	}

	return makeSBOMWriter(o.Outputs, o.File, encoders)
}

func (o *Output) Encoders() ([]sbom.FormatEncoder, error) {
	// setup all encoders based on the configuration
	var list encoderList

	// in the future there will be application configuration options that can be used to set the default output format
	list.addWithErr(template.ID)(o.OutputTemplate.formatEncoders())
	list.add(syftjson.ID)(syftjson.NewFormatEncoder())
	list.add(table.ID)(table.NewFormatEncoder())
	list.add(text.ID)(text.NewFormatEncoder())
	list.add(github.ID)(github.NewFormatEncoder())
	list.addWithErr(cyclonedxxml.ID)(cycloneDxXMLEncoders())
	list.addWithErr(cyclonedxjson.ID)(cycloneDxJSONEncoders())
	list.addWithErr(spdxjson.ID)(spdxJSONEncoders())
	list.addWithErr(spdxtagvalue.ID)(spdxTagValueEncoders())

	return list.encoders, list.err
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

// TODO: when application configuration is made for this format then this should be ported to the options object
// that is created for that configuration (as done with the template output option)
func cycloneDxXMLEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)
	for _, v := range cyclonedxxml.SupportedVersions() {
		enc, err := cyclonedxxml.NewFormatEncoderWithConfig(cyclonedxxml.EncoderConfig{Version: v})
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
		enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.EncoderConfig{Version: v})
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
		enc, err := spdxjson.NewFormatEncoderWithConfig(spdxjson.EncoderConfig{Version: v})
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
		enc, err := spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.EncoderConfig{Version: v})
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

func supportedIDs() []sbom.FormatID {
	encs := []sbom.FormatID{
		// encoders that support a single version
		syftjson.ID,
		github.ID,
		table.ID,
		text.ID,
		template.ID,

		// encoders that support multiple versions
		cyclonedxxml.ID,
		cyclonedxjson.ID,
		spdxtagvalue.ID,
		spdxjson.ID,
	}

	return encs
}

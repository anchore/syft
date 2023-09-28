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
	list.attempt(template.ID)(o.OutputTemplate.formatEncoder())
	list.add(syftjson.ID)(syftjson.DefaultFormatEncoder())
	list.add(table.ID)(table.DefaultFormatEncoder())
	list.add(text.ID)(text.DefaultFormatEncoder())
	list.add(github.ID)(github.DefaultFormatEncoder())
	list.add(cyclonedxxml.ID)(cyclonedxxml.DefaultFormatEncoder())
	list.add(cyclonedxjson.ID)(cyclonedxjson.DefaultFormatEncoder())
	list.add(spdxjson.ID)(spdxjson.DefaultFormatEncoder())
	list.add(spdxtagvalue.ID)(spdxtagvalue.DefaultFormatEncoder())

	o.encoders = list.encoders

	return list.err
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

func (l *encoderList) attempt(name sbom.FormatID) func(sbom.FormatEncoder, error) {
	return func(enc sbom.FormatEncoder, err error) {
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

func (l *encoderList) add(name sbom.FormatID) func(sbom.FormatEncoder) {
	return func(enc sbom.FormatEncoder) {
		if enc == nil {
			l.err = multierror.Append(l.err, fmt.Errorf("unable to configure %q format encoder: nil encoder returned", name))
			return
		}
		l.encoders = append(l.encoders, enc)
	}
}

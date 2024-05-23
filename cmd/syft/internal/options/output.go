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
	clio.FieldDescriber
} = (*Output)(nil)

// Output has the standard output options syft accepts: multiple -o, --file, --template
type Output struct {
	AllowableOptions     []string `yaml:"-" json:"-" mapstructure:"-"`
	AllowMultipleOutputs bool     `yaml:"-" json:"-" mapstructure:"-"`
	AllowToFile          bool     `yaml:"-" json:"-" mapstructure:"-"`
	Outputs              []string `yaml:"output" json:"output" mapstructure:"output"` // -o, the format to use for output
	OutputFile           `yaml:",inline" json:"" mapstructure:",squash"`
	Format               `yaml:"format" json:"format" mapstructure:"format"`
}

func DefaultOutput() Output {
	return Output{
		AllowMultipleOutputs: true,
		AllowToFile:          true,
		Outputs:              []string{string(table.ID)},
		OutputFile: OutputFile{
			Enabled: true,
		},
		Format: DefaultFormat(),
	}
}

func (o *Output) PostLoad() error {
	var errs error
	for _, loader := range []clio.PostLoader{&o.OutputFile, &o.Format} {
		if err := loader.PostLoad(); err != nil {
			errs = multierror.Append(errs, err)
		}
	}

	return errs
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

func (o *Output) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.Outputs, `the output format(s) of the SBOM report (options: syft-table, syft-text, syft-json, spdx-json, ...)
to specify multiple output files in differing formats, use a list:
output:
  - "syft-json=<syft-json-output-file>"
  - "spdx-json=<spdx-json-output-file>"
`)
}

func (o Output) SBOMWriter() (sbom.Writer, error) {
	names := o.OutputNameSet()

	if len(o.Outputs) > 1 && !o.AllowMultipleOutputs {
		return nil, fmt.Errorf("only one output format is allowed (given %d: %s)", len(o.Outputs), names)
	}

	usesTemplateOutput := names.Has(string(template.ID))

	if usesTemplateOutput && o.Format.Template.Path == "" {
		return nil, fmt.Errorf(`must specify path to template file when using "template" output format`)
	}

	encoders, err := o.Encoders()
	if err != nil {
		return nil, err
	}

	if !o.AllowToFile {
		for _, opt := range o.Outputs {
			if strings.Contains(opt, "=") {
				return nil, fmt.Errorf("file output is not allowed ('-o format=path' should be '-o format')")
			}
		}
	}

	return makeSBOMWriter(o.Outputs, o.LegacyFile, encoders)
}

func (o Output) OutputNameSet() *strset.Set {
	names := strset.New()
	for _, output := range o.Outputs {
		fields := strings.Split(output, "=")
		names.Add(fields[0])
	}

	return names
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

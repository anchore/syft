package options

import (
	"fmt"
	"slices"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/sbom"
)

// MultiOutput has the standard output options syft accepts: multiple -o, --file, --template
type MultiOutput struct {
	Outputs            []string `yaml:"output" json:"output" mapstructure:"output"` // -o, the format to use for output
	OutputFile         `yaml:",inline" json:"" mapstructure:",squash"`
	OutputTemplatePath string `yaml:"output-template-path" json:"output-template-path" mapstructure:"output-template-path"` // -t template file to use for output
}

var _ interface {
	clio.FlagAdder
} = (*MultiOutput)(nil)

func DefaultOutput() MultiOutput {
	return MultiOutput{
		Outputs: []string{string(table.ID)},
	}
}

func (o *MultiOutput) AddFlags(flags clio.FlagSet) {
	flags.StringArrayVarP(&o.Outputs, "output", "o",
		fmt.Sprintf("report output format (<format>=<file> to output to a file), formats=%v", formats.AllIDs()))

	flags.StringVarP(&o.OutputTemplatePath, "template", "t",
		"specify the path to a Go template file")
}

func (o *MultiOutput) SBOMWriter() (sbom.Writer, error) {
	return makeSBOMWriter(o.Outputs, o.File, o.OutputTemplatePath)
}

// SingleOutput allows only 1 output to be specified, with a user able to set what options are allowed by setting AllowableOptions
type SingleOutput struct {
	AllowableOptions   []string `yaml:"-" json:"-" mapstructure:"-"`
	Output             string   `yaml:"output" json:"output" mapstructure:"output"`
	OutputTemplatePath string   `yaml:"output-template-path" json:"output-template-path" mapstructure:"output-template-path"` // -t template file to use for output
}

var _ clio.FlagAdder = (*SingleOutput)(nil)

func (o *SingleOutput) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Output, "output", "o",
		fmt.Sprintf("report output format, options=%v", o.AllowableOptions))

	if slices.Contains(o.AllowableOptions, template.ID.String()) {
		flags.StringVarP(&o.OutputTemplatePath, "template", "t",
			"specify the path to a Go template file")
	}
}

func (o *SingleOutput) SBOMWriter(file string) (sbom.Writer, error) {
	return makeSBOMWriter([]string{o.Output}, file, o.OutputTemplatePath)
}

// Deprecated: OutputFile is only the --file argument
type OutputFile struct {
	File string `yaml:"file" json:"file" mapstructure:"file"` // --file, the file to write report output to
}

var _ interface {
	clio.FlagAdder
	clio.PostLoader
} = (*OutputFile)(nil)

func (o *OutputFile) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.File, "file", "",
		"file to write the default report output to (default is STDOUT)")

	if pfp, ok := flags.(fangs.PFlagSetProvider); ok {
		flagSet := pfp.PFlagSet()
		flagSet.Lookup("file").Deprecated = "use: output"
	}
}

func (o *OutputFile) PostLoad() error {
	if o.File != "" {
		file, err := expandFilePath(o.File)
		if err != nil {
			return err
		}
		o.File = file
	}
	return nil
}

func (o *OutputFile) SBOMWriter(f sbom.Format) (sbom.Writer, error) {
	return makeSBOMWriterForFormat(f, o.File)
}

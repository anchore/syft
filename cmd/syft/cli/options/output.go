package options

import (
	"fmt"
	"github.com/anchore/clio"

	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/formats/table"
)

type Output struct {
	Outputs            []string `yaml:"output" json:"output" mapstructure:"output"`                                           // -o, the format to use for output
	OutputTemplatePath string   `yaml:"output-template-path" json:"output-template-path" mapstructure:"output-template-path"` // -t template file to use for output
	OutputFile         `yaml:",inline" json:"" mapstructure:",squash"`
}

var _ interface {
	clio.FlagAdder
} = (*Output)(nil)

func OutputDefault() Output {
	return Output{
		Outputs: []string{string(table.ID)},
	}
}

func (o *Output) AddFlags(flags clio.FlagSet) {
	flags.StringArrayVarP(&o.Outputs, "output", "o",
		fmt.Sprintf("report output format, options=%v", formats.AllIDs()))

	flags.StringVarP(&o.OutputTemplatePath, "template", "t",
		"specify the path to a Go template file")
}

type SingleOutput struct {
	AllowableOptions   []string `yaml:"-" json:"-" mapstructure:"-"`
	Output             string   `yaml:"output" json:"output" mapstructure:"output"`
	OutputTemplatePath string   `yaml:"output-template-path" json:"output-template-path" mapstructure:"output-template-path"` // -t template file to use for output
}

var _ clio.FlagAdder = (*SingleOutput)(nil)

func (o *SingleOutput) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Output, "output", "o",
		fmt.Sprintf("report output format, options=%v", o.AllowableOptions))

	flags.StringVarP(&o.OutputTemplatePath, "template", "t",
		"specify the path to a Go template file")
}

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

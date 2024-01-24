package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/format/template"
)

var _ clio.FlagAdder = (*FormatTemplate)(nil)

type FormatTemplate struct {
	Enabled bool   `yaml:"-" json:"-" mapstructure:"-"`
	Path    string `yaml:"path" json:"path" mapstructure:"path"` // -t template file to use for output
	Legacy  bool   `yaml:"legacy" json:"legacy" mapstructure:"legacy"`
}

func DefaultFormatTemplate() FormatTemplate {
	return FormatTemplate{
		Enabled: true,
	}
}

func (o *FormatTemplate) AddFlags(flags clio.FlagSet) {
	if o.Enabled {
		flags.StringVarP(&o.Path, "template", "t",
			"specify the path to a Go template file")
	}
}

func (o FormatTemplate) config() template.EncoderConfig {
	return template.EncoderConfig{
		TemplatePath: o.Path,
		Legacy:       o.Legacy,
	}
}

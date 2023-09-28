package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/format/template"
	"github.com/anchore/syft/syft/sbom"
)

var _ clio.FlagAdder = (*OutputTemplate)(nil)

type OutputTemplate struct {
	Path string `yaml:"path" json:"path" mapstructure:"path"` // -t template file to use for output
}

func (o *OutputTemplate) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Path, "template", "t",
		"specify the path to a Go template file")
}

func (o OutputTemplate) formatEncoder() (sbom.FormatEncoder, error) {
	return template.NewFormatEncoder(template.EncoderConfig{
		TemplatePath: o.Path,
	})
}

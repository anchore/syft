package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/format/template"
	"github.com/anchore/syft/syft/sbom"
)

var _ clio.FlagAdder = (*OutputTemplate)(nil)

type OutputTemplate struct {
	Enabled bool   `yaml:"-" json:"-" mapstructure:"-"`
	Path    string `yaml:"path" json:"path" mapstructure:"path"` // -t template file to use for output
}

func (o *OutputTemplate) AddFlags(flags clio.FlagSet) {
	if o.Enabled {
		flags.StringVarP(&o.Path, "template", "t",
			"specify the path to a Go template file")
	}
}

func (o OutputTemplate) formatEncoders() ([]sbom.FormatEncoder, error) {
	if !o.Enabled {
		return nil, nil
	}
	enc, err := template.NewFormatEncoder(template.EncoderConfig{
		TemplatePath: o.Path,
	})
	return []sbom.FormatEncoder{enc}, err
}

package options

import (
	"github.com/anchore/syft/syft/format/spdxjson"
)

type FormatSPDXJSON struct {
	Pretty *bool `yaml:"pretty" json:"pretty" mapstructure:"pretty"`
}

func DefaultFormatSPDXJSON() FormatSPDXJSON {
	return FormatSPDXJSON{}
}

func (o FormatSPDXJSON) config(v string) spdxjson.EncoderConfig {
	c := spdxjson.DefaultEncoderConfig()
	c.Version = v
	if o.Pretty != nil {
		c.Pretty = *o.Pretty
	}
	return c
}

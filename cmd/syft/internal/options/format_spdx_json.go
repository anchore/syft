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
	var pretty bool
	if o.Pretty != nil {
		pretty = *o.Pretty
	}
	return spdxjson.EncoderConfig{
		Version: v,
		Pretty:  pretty,
	}
}

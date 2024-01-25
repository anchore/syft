package options

import (
	"github.com/anchore/syft/syft/format/cyclonedxjson"
)

type FormatCyclonedxJSON struct {
	Pretty *bool `yaml:"pretty" json:"pretty" mapstructure:"pretty"`
}

func DefaultFormatCyclonedxJSON() FormatCyclonedxJSON {
	return FormatCyclonedxJSON{}
}

func (o FormatCyclonedxJSON) config(version string) cyclonedxjson.EncoderConfig {
	var pretty bool
	if o.Pretty != nil {
		pretty = *o.Pretty
	}
	return cyclonedxjson.EncoderConfig{
		Version: version,
		Pretty:  pretty,
	}
}

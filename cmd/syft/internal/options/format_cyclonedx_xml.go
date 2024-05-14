package options

import (
	"github.com/anchore/syft/syft/format/cyclonedxxml"
)

type FormatCyclonedxXML struct {
	Pretty *bool `yaml:"pretty" json:"pretty" mapstructure:"pretty"`
}

func DefaultFormatCyclonedxXML() FormatCyclonedxXML {
	return FormatCyclonedxXML{}
}

func (o FormatCyclonedxXML) config(version string) cyclonedxxml.EncoderConfig {
	var pretty bool
	if o.Pretty != nil {
		pretty = *o.Pretty
	}
	return cyclonedxxml.EncoderConfig{
		Version: version,
		Pretty:  pretty,
	}
}

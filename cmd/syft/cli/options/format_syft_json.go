package options

import (
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

type FormatSyftJSON struct {
	Legacy  bool `yaml:"legacy" json:"legacy" mapstructure:"legacy"`
	Compact bool `yaml:"compact" json:"compact" mapstructure:"compact"`
}

func DefaultFormatJSON() FormatSyftJSON {
	return FormatSyftJSON{
		Legacy:  false,
		Compact: false,
	}
}

func (o FormatSyftJSON) formatEncoders() ([]sbom.FormatEncoder, error) {
	enc, err := syftjson.NewFormatEncoderWithConfig(o.buildConfig())
	return []sbom.FormatEncoder{enc}, err
}

func (o FormatSyftJSON) buildConfig() syftjson.EncoderConfig {
	return syftjson.EncoderConfig{
		Legacy:  o.Legacy,
		Compact: o.Compact,
	}
}

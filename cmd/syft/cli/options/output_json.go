package options

import (
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

type OutputJSON struct {
	Legacy bool `yaml:"legacy" json:"legacy" mapstructure:"legacy"`
}

func (o OutputJSON) formatEncoders() ([]sbom.FormatEncoder, error) {
	enc, err := syftjson.NewFormatEncoderWithConfig(
		syftjson.EncoderConfig{
			Legacy: o.Legacy,
		},
	)
	return []sbom.FormatEncoder{enc}, err
}

package options

import (
	"github.com/anchore/syft/syft/format/spdxjson"
)

type FormatSPDXJSON struct {
	Pretty            *bool `yaml:"pretty" json:"pretty" mapstructure:"pretty"`
	DeterministicUUID *bool `yaml:"deterministic-uuid" json:"deterministic-uuid" mapstructure:"deterministic-uuid"`
}

func DefaultFormatSPDXJSON() FormatSPDXJSON {
	return FormatSPDXJSON{}
}

func (o FormatSPDXJSON) config(v string) spdxjson.EncoderConfig {
	var pretty, deterministicUUID bool
	if o.Pretty != nil {
		pretty = *o.Pretty
	}
	if o.DeterministicUUID != nil {
		deterministicUUID = *o.DeterministicUUID
	}
	return spdxjson.EncoderConfig{
		Version:           v,
		Pretty:            pretty,
		DeterministicUUID: deterministicUUID,
	}
}

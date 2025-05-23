package options

import (
	"github.com/anchore/syft/syft/format/spdxjson"
)

type FormatSPDXJSON struct {
	Pretty            *bool  `yaml:"pretty" json:"pretty" mapstructure:"pretty"`
	DeterministicUUID *bool  `yaml:"deterministic-uuid" json:"deterministic-uuid" mapstructure:"deterministic-uuid"`
	CreatedTime       *int64 `yaml:"created-time" json:"created-time" mapstructure:"created-time"`
}

func DefaultFormatSPDXJSON() FormatSPDXJSON {
	return FormatSPDXJSON{}
}

func (o FormatSPDXJSON) config(v string) spdxjson.EncoderConfig {
	var pretty, deterministicUUID bool
	var createdTime *int64
	if o.Pretty != nil {
		pretty = *o.Pretty
	}
	if o.DeterministicUUID != nil {
		deterministicUUID = *o.DeterministicUUID
	}
	if o.CreatedTime != nil {
		createdTime = o.CreatedTime
	}
	return spdxjson.EncoderConfig{
		Version:           v,
		Pretty:            pretty,
		DeterministicUUID: deterministicUUID,
		CreatedTime:       createdTime,
	}
}

package options

import (
	"fmt"
	"time"

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

func (o FormatSPDXJSON) Validate() error {
	if o.CreatedTime != nil {
		if *o.CreatedTime < 0 {
			return fmt.Errorf("created-time must be a non-negative Unix timestamp")
		}
	}
	return nil
}

func (o FormatSPDXJSON) config(v string) spdxjson.EncoderConfig {
	var pretty, deterministicUUID bool
	var createdTime *time.Time
	if o.Pretty != nil {
		pretty = *o.Pretty
	}
	if o.DeterministicUUID != nil {
		deterministicUUID = *o.DeterministicUUID
	}
	if o.CreatedTime != nil {
		ts := time.Unix(*o.CreatedTime, 0)
		createdTime = &ts
	}
	return spdxjson.EncoderConfig{
		Version:           v,
		Pretty:            pretty,
		DeterministicUUID: deterministicUUID,
		CreatedTime:       createdTime,
	}
}

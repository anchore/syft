package options

import (
	"github.com/anchore/clio"
)

type Attest struct {
	// IMPORTANT: do not show the attestation key/password in any YAML/JSON output (sensitive information)
	Key      secret `yaml:"key" json:"key" mapstructure:"key"`
	Password secret `yaml:"password" json:"password" mapstructure:"password"`
}

var _ clio.FlagAdder = (*Attest)(nil)

func (o Attest) AddFlags(flags clio.FlagSet) {
	flags.StringVarP((*string)(&o.Key), "key", "k", "the key to use for the attestation")
}

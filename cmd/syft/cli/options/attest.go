package options

import (
	"github.com/anchore/clio"
)

type Attest struct {
	// IMPORTANT: do not show the attestation key/password in any YAML/JSON output (sensitive information)
	Key      string `yaml:"-" json:"-" mapstructure:"key"`
	Password string `yaml:"-" json:"-" mapstructure:"password"`
}

var _ clio.FlagAdder = (*Attest)(nil)

func (o Attest) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Key, "key", "k", "the key to use for the attestation")
}

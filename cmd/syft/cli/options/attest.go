package options

import (
	"github.com/anchore/fangs"
)

type Attest struct {
	// IMPORTANT: do not show the attestation key/password in any YAML/JSON output (sensitive information)
	Key      string `yaml:"-" json:"-" mapstructure:"key"`
	Password string `yaml:"-" json:"-" mapstructure:"password"`
}

var _ fangs.FlagAdder = (*Attest)(nil)

func (o Attest) AddFlags(flags fangs.FlagSet) {
	flags.StringVarP(&o.Key, "key", "k", "the key to use for the attestation")
}

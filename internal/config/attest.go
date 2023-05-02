package config

type attest struct {
	// IMPORTANT: do not show the attestation key/password in any YAML/JSON output (sensitive information)
	Key      string `yaml:"-" json:"-" mapstructure:"key"`
	Password string `yaml:"-" json:"-" mapstructure:"password"`
}

func newAttest() attest {
	return attest{}
}

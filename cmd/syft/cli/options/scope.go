package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/source"
)

type scope struct {
	Enabled bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Scope   string `yaml:"scope" json:"scope" mapstructure:"scope"`
}

var _ clio.PostLoader = (*scope)(nil)

func (opt *scope) PostLoad() error {
	s := opt.GetScope()
	if s == source.UnknownScope {
		return fmt.Errorf("bad scope value %v", opt.Scope)
	}
	return nil
}

func (opt scope) GetScope() source.Scope {
	return source.ParseScope(opt.Scope)
}

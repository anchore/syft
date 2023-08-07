package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/source"
)

type catalogerOptions struct {
	Enabled bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Scope   string `yaml:"scope" json:"scope" mapstructure:"scope"`
}

var _ clio.PostLoader = (*catalogerOptions)(nil)

func (opt *catalogerOptions) PostLoad() error {
	s := opt.SourceScope()
	if s == source.UnknownScope {
		return fmt.Errorf("bad scope value %v", s)
	}
	return nil
}

func (opt *catalogerOptions) SourceScope() source.Scope {
	return source.ParseScope(opt.Scope)
}

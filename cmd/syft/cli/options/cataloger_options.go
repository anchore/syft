package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/source"
)

type catalogerOptions struct {
	Enabled bool         `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Scope   source.Scope `yaml:"scope" json:"scope" mapstructure:"scope"`
}

var _ clio.PostLoader = (*catalogerOptions)(nil)

func (opt *catalogerOptions) PostLoad() error {
	s := source.ParseScope(opt.Scope.String())
	if s == source.UnknownScope {
		return fmt.Errorf("bad scope value %v", opt.Scope)
	}
	return nil
}

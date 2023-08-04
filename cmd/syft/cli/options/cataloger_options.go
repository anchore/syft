package options

import (
	"fmt"

	"github.com/anchore/fangs"
	"github.com/anchore/syft/syft/source"
)

type catalogerOptions struct {
	Enabled bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Scope   string `yaml:"scope" json:"scope" mapstructure:"scope"`
}

var _ fangs.PostLoader = (*catalogerOptions)(nil)

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

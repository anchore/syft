package config

import (
	"fmt"

	"github.com/anchore/fangs/config"
	"github.com/anchore/syft/syft/source"
)

type catalogerOptions struct {
	Enabled  bool         `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Scope    string       `yaml:"scope" json:"scope" mapstructure:"scope"`
	ScopeOpt source.Scope `yaml:"-" json:"-"`
}

var _ config.PostLoad = (*catalogerOptions)(nil)

func newCatalogerOptions(enabled bool, scope source.Scope) catalogerOptions {
	return catalogerOptions{
		Enabled:  enabled,
		Scope:    string(scope),
		ScopeOpt: scope,
	}
}

func (cfg *catalogerOptions) PostLoad() error {
	scopeOption := source.ParseScope(cfg.Scope)
	if scopeOption == source.UnknownScope {
		return fmt.Errorf("bad scope value %q", cfg.Scope)
	}
	cfg.ScopeOpt = scopeOption

	return nil
}

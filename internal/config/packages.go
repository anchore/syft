package config

import (
	"fmt"

	"github.com/anchore/syft/syft/source"
)

type Packages struct {
	CatalogingEnabled bool         `yaml:"cataloging-enabled" json:"cataloging-enabled" mapstructure:"cataloging-enabled"`
	Scope             string       `yaml:"scope" json:"scope" mapstructure:"scope"`
	ScopeOpt          source.Scope `yaml:"-" json:"-"`
}

func (cfg *Packages) build() error {
	scopeOption := source.ParseScope(cfg.Scope)
	if scopeOption == source.UnknownScope {
		return fmt.Errorf("bad scope value %q", cfg.Scope)
	}
	cfg.ScopeOpt = scopeOption

	return nil
}

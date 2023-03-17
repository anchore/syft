package config

import (
	"fmt"

	"github.com/spf13/viper"

	"github.com/anchore/syft/syft/source"
)

type catalogerOptions struct {
	Enabled  bool         `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Scope    string       `yaml:"scope" json:"scope" mapstructure:"scope"`
	Golang   golang       `yaml:"golang" json:"golang" mapstructure:"golang"`
	ScopeOpt source.Scope `yaml:"-" json:"-"`
}

func (cfg catalogerOptions) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("package.cataloger.enabled", true)
	cfg.Golang.loadDefaultValues(v)
}

func (cfg *catalogerOptions) parseConfigValues() error {
	scopeOption := source.ParseScope(cfg.Scope)
	if scopeOption == source.UnknownScope {
		return fmt.Errorf("bad scope value %q", cfg.Scope)
	}
	cfg.ScopeOpt = scopeOption

	return nil
}

package config

import (
	"fmt"

	"github.com/anchore/syft/syft/source"
)

type FileMetadata struct {
	CatalogingEnabled bool         `yaml:"cataloging-enabled" json:"cataloging-enabled" mapstructure:"cataloging-enabled"`
	Scope             string       `yaml:"scope" json:"scope" mapstructure:"scope"`
	ScopeOpt          source.Scope `yaml:"-" json:"-"`
	Digests           []string     `yaml:"digests" json:"digests" mapstructure:"digests"`
}

func (cfg *FileMetadata) build() error {
	scopeOption := source.ParseScope(cfg.Scope)
	if scopeOption == source.UnknownScope {
		return fmt.Errorf("bad scope value %q", cfg.Scope)
	}
	cfg.ScopeOpt = scopeOption

	return nil
}

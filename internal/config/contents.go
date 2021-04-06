package config

import (
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/source"
	"github.com/spf13/viper"
)

type contents struct {
	Cataloger          catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	SkipFilesAboveSize int64            `yaml:"skip-files-above-size" json:"skip-files-above-size" mapstructure:"skip-files-above-size"`
	Globs              []string         `yaml:"globs" json:"globs" mapstructure:"globs"`
}

func (cfg contents) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("contents.cataloger.enabled", true)
	v.SetDefault("contents.cataloger.scope", source.SquashedScope)
	v.SetDefault("contents.skip-files-above-size", 1*file.MB)
	v.SetDefault("contents.globs", []string{})
}

func (cfg *contents) parseConfigValues() error {
	return cfg.Cataloger.parseConfigValues()
}

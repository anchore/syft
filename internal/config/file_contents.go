package config

import (
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/source"
	"github.com/spf13/viper"
)

type fileContents struct {
	Cataloger          catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	SkipFilesAboveSize int64            `yaml:"skip-files-above-size" json:"skip-files-above-size" mapstructure:"skip-files-above-size"`
	Globs              []string         `yaml:"globs" json:"globs" mapstructure:"globs"`
}

func (cfg fileContents) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("file-contents.cataloger.enabled", catalogerEnabledDefault)
	v.SetDefault("file-contents.cataloger.scope", source.SquashedScope)
	v.SetDefault("file-contents.skip-files-above-size", 1*file.MB)
	v.SetDefault("file-contents.globs", []string{})
}

func (cfg *fileContents) parseConfigValues() error {
	return cfg.Cataloger.parseConfigValues()
}

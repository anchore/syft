package config

import (
	"github.com/anchore/syft/syft/cataloger/files/filecontents"
	"github.com/anchore/syft/syft/file"
	"github.com/spf13/viper"
)

type fileContents struct {
	SkipFilesAboveSize int64    `yaml:"skip-files-above-size" json:"skip-files-above-size" mapstructure:"skip-files-above-size"`
	Globs              []string `yaml:"globs" json:"globs" mapstructure:"globs"`
}

func (cfg fileContents) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("file-contents.skip-files-above-size", 1*file.MB)
	v.SetDefault("file-contents.globs", []string{})
}

func (cfg fileContents) ToConfig() filecontents.Config {
	return filecontents.Config{
		Globs:                     cfg.Globs,
		SkipFilesAboveSizeInBytes: cfg.SkipFilesAboveSize,
	}
}

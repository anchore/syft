package config

import "github.com/spf13/viper"

type sourceCfg struct {
	Name    string     `json:"name" yaml:"name" mapstructure:"name"`
	Version string     `json:"version" yaml:"version" mapstructure:"version"`
	File    fileSource `json:"file" yaml:"file" mapstructure:"file"`
}

type fileSource struct {
	Digests []string `json:"digests" yaml:"digests" mapstructure:"digests"`
}

func (cfg sourceCfg) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("source.file.digests", []string{"sha256"})
}

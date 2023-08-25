package config

import (
	"github.com/spf13/viper"
)

type python struct {
	GuessUnpinnedRequirements bool `json:"guess-unpinned-requirements" yaml:"guess-unpinned-requirements" mapstructure:"guess-unpinned-requirements"`
}

func (cfg python) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("python.guess-unpinned-requirements", false)
}

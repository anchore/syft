package options

import (
	"fmt"
	"strings"

	"github.com/scylladb/go-set/strset"
)

type sourceConfig struct {
	Name     string      `json:"name" yaml:"name" mapstructure:"name"`
	Version  string      `json:"version" yaml:"version" mapstructure:"version"`
	BasePath string      `yaml:"base-path" json:"base-path" mapstructure:"base-path"` // specify base path for all file paths
	File     fileSource  `json:"file" yaml:"file" mapstructure:"file"`
}

type fileSource struct {
	Digests []string `json:"digests" yaml:"digests" mapstructure:"digests"`
}

func defaultSourceCfg() sourceCfg {
	return sourceCfg{
		File: fileSource{
			Digests: []string{"sha256"},
		},
	}
}

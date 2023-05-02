package config

import (
	"github.com/anchore/syft/syft/source"
)

type FileMetadata struct {
	Cataloger catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	Digests   []string         `yaml:"digests" json:"digests" mapstructure:"digests"`
}

func newFileMetadata(enabled bool) FileMetadata {
	return FileMetadata{
		Cataloger: newCatalogerOptions(enabled, source.SquashedScope),
		Digests:   []string{"sha256"},
	}
}

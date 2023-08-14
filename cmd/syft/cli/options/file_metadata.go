package options

import (
	"github.com/anchore/syft/syft/source"
)

type fileMetadata struct {
	Cataloger catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	Digests   []string         `yaml:"digests" json:"digests" mapstructure:"digests"`
}

func fileMetadataDefault() fileMetadata {
	return fileMetadata{
		Cataloger: catalogerOptions{
			Scope: source.SquashedScope.String(),
		},
		Digests: []string{"sha256"},
	}
}

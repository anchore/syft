package options

import (
	"github.com/anchore/syft/syft/source"
)

type fileMetadata struct {
	Cataloger Cataloger `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	Digests   []string  `yaml:"digests" json:"digests" mapstructure:"digests"`
}

func defaultFileMetadata() fileMetadata {
	return fileMetadata{
		Cataloger: Cataloger{
			Scope: source.SquashedScope.String(),
		},
		Digests: []string{"sha256"},
	}
}

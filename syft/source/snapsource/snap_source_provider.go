package snapsource

import (
	"context"
	"crypto"

	"github.com/anchore/syft/syft/source"
)

// NewSourceProvider creates a new provider for snap files
func NewSourceProvider(path string, exclude source.ExcludeConfig, digestAlgorithms []crypto.Hash, alias source.Alias) source.Provider {
	return &snapSourceProvider{
		path:             path,
		exclude:          exclude,
		digestAlgorithms: digestAlgorithms,
		alias:            alias,
	}
}

type snapSourceProvider struct {
	path             string
	exclude          source.ExcludeConfig
	digestAlgorithms []crypto.Hash
	alias            source.Alias
}

func (p snapSourceProvider) Name() string {
	return "snap"
}

func (p snapSourceProvider) Provide(_ context.Context) (source.Source, error) {
	return New(
		Config{
			Request:          p.path,
			Exclude:          p.exclude,
			DigestAlgorithms: p.digestAlgorithms,
			Alias:            p.alias,
		},
	)
}

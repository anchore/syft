package snapsource

import (
	"context"
	"crypto"

	"github.com/anchore/syft/syft/source"
)

type snapSourceProvider struct {
	local            bool
	path             string
	exclude          source.ExcludeConfig
	digestAlgorithms []crypto.Hash
	alias            source.Alias
}

// NewLocalSourceProvider creates a new provider for snap files from a local path.
func NewLocalSourceProvider(path string, exclude source.ExcludeConfig, digestAlgorithms []crypto.Hash, alias source.Alias) source.Provider {
	return &snapSourceProvider{
		local:            true,
		path:             path,
		exclude:          exclude,
		digestAlgorithms: digestAlgorithms,
		alias:            alias,
	}
}

// NewRemoteSourceProvider creates a new provider for snap files from a remote location.
func NewRemoteSourceProvider(path string, exclude source.ExcludeConfig, digestAlgorithms []crypto.Hash, alias source.Alias) source.Provider {
	return &snapSourceProvider{
		path:             path,
		exclude:          exclude,
		digestAlgorithms: digestAlgorithms,
		alias:            alias,
	}
}

func (p snapSourceProvider) Name() string {
	return "snap"
}

func (p snapSourceProvider) Provide(_ context.Context) (source.Source, error) {
	cfg := Config{
		Request:          p.path,
		Exclude:          p.exclude,
		DigestAlgorithms: p.digestAlgorithms,
		Alias:            p.alias,
	}
	if p.local {
		return NewFromLocal(cfg)
	}
	return NewFromRemote(cfg)
}

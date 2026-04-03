package appimagesource

import (
	"context"
	"crypto"

	"github.com/anchore/syft/syft/source"
)

type appImageSourceProvider struct {
	path             string
	exclude          source.ExcludeConfig
	digestAlgorithms []crypto.Hash
	alias            source.Alias
}

// NewSourceProvider creates a new provider for AppImage files from a local path.
func NewSourceProvider(path string, exclude source.ExcludeConfig, digestAlgorithms []crypto.Hash, alias source.Alias) source.Provider {
	return &appImageSourceProvider{
		path:             path,
		exclude:          exclude,
		digestAlgorithms: digestAlgorithms,
		alias:            alias,
	}
}

func (p appImageSourceProvider) Name() string {
	return "appimage"
}

func (p appImageSourceProvider) Provide(_ context.Context) (source.Source, error) {
	cfg := Config{
		Request:          p.path,
		Exclude:          p.exclude,
		DigestAlgorithms: p.digestAlgorithms,
		Alias:            p.alias,
	}
	return NewFromPath(cfg)
}

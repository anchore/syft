package filesource

import (
	"context"
	"crypto"
	"fmt"

	"github.com/mitchellh/go-homedir"

	"github.com/anchore/syft/syft/source"
)

func NewSourceProvider(path string, exclude source.ExcludeConfig, digestAlgorithms []crypto.Hash, alias source.Alias, basePath string) source.Provider {
	return &fileSourceProvider{
		path:             path,
		basePath:         basePath,
		exclude:          exclude,
		digestAlgorithms: digestAlgorithms,
		alias:            alias,
	}
}

type fileSourceProvider struct {
	path             string
	basePath         string
	exclude          source.ExcludeConfig
	digestAlgorithms []crypto.Hash
	alias            source.Alias
}

func (p fileSourceProvider) Name() string {
	return "local-file"
}

func (p fileSourceProvider) Provide(_ context.Context) (source.Source, error) {
	location, err := homedir.Expand(p.path)
	if err != nil {
		return nil, fmt.Errorf("unable to expand potential directory path: %w", err)
	}

	return New(
		Config{
			Path:             location,
			Base:             p.basePath,
			Exclude:          p.exclude,
			DigestAlgorithms: p.digestAlgorithms,
			Alias:            p.alias,
		},
	)
}

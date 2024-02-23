package filesource

import (
	"context"
	"crypto"
	"fmt"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"

	"github.com/anchore/syft/syft/source"
)

func NewSourceProvider(path string, exclude source.ExcludeConfig, digestAlgorithms []crypto.Hash, alias source.Alias) source.Provider {
	return &fileSourceProvider{
		path:             path,
		exclude:          exclude,
		digestAlgorithms: digestAlgorithms,
		alias:            alias,
	}
}

type fileSourceProvider struct {
	path             string
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

	fs := afero.NewOsFs()
	fileMeta, err := fs.Stat(location)
	if err != nil {
		return nil, fmt.Errorf("unable to stat location: %w", err)
	}

	if fileMeta.IsDir() {
		return nil, fmt.Errorf("not a file source: %s", p.path)
	}

	return New(
		Config{
			Path:             location,
			Exclude:          p.exclude,
			DigestAlgorithms: p.digestAlgorithms,
			Alias:            p.alias,
		},
	)
}

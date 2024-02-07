package filesource

import (
	"context"
	"crypto"
	"fmt"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"

	"github.com/anchore/syft/syft/source"
)

func NewSourceProvider(exclude source.ExcludeConfig, digestAlgorithms []crypto.Hash, alias source.Alias) source.Provider {
	return &sourceProvider{
		exclude:          exclude,
		digestAlgorithms: digestAlgorithms,
		alias:            alias,
	}
}

type sourceProvider struct {
	exclude          source.ExcludeConfig
	digestAlgorithms []crypto.Hash
	alias            source.Alias
}

func (l sourceProvider) Name() string {
	return "local-file"
}

func (l sourceProvider) Provide(_ context.Context, userInput string) (source.Source, error) {
	location, err := homedir.Expand(userInput)
	if err != nil {
		return nil, fmt.Errorf("unable to expand potential directory path: %w", err)
	}

	fs := afero.NewOsFs()
	fileMeta, err := fs.Stat(location)
	if err != nil {
		return nil, fmt.Errorf("unable to stat location: %w", err)
	}

	if fileMeta.IsDir() {
		return nil, fmt.Errorf("not a file source: %s", userInput)
	}

	return NewFromFile(
		FileConfig{
			Path:             location,
			Exclude:          l.exclude,
			DigestAlgorithms: l.digestAlgorithms,
			Alias:            l.alias,
		},
	)
}

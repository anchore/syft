package directorysource

import (
	"context"
	"fmt"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"

	"github.com/anchore/syft/syft/source"
)

func NewSourceProvider(path string, exclude source.ExcludeConfig, alias source.Alias, basePath string) source.Provider {
	return &directorySourceProvider{
		path:     path,
		basePath: basePath,
		exclude:  exclude,
		alias:    alias,
	}
}

type directorySourceProvider struct {
	path     string
	basePath string
	exclude  source.ExcludeConfig
	alias    source.Alias
}

func (l directorySourceProvider) Name() string {
	return "local-directory"
}

func (l directorySourceProvider) Provide(_ context.Context) (source.Source, error) {
	location, err := homedir.Expand(l.path)
	if err != nil {
		return nil, fmt.Errorf("unable to expand potential directory path: %w", err)
	}

	fs := afero.NewOsFs()
	fileMeta, err := fs.Stat(location)
	if err != nil {
		return nil, fmt.Errorf("unable to stat location: %w", err)
	}

	if !fileMeta.IsDir() {
		return nil, fmt.Errorf("not a directory source: %s", l.path)
	}

	return New(
		Config{
			Path:    location,
			Base:    basePath(l.basePath, location),
			Exclude: l.exclude,
			Alias:   l.alias,
		},
	)
}

// FIXME why is the base always being set instead of left as empty string?
func basePath(base, location string) string {
	if base == "" {
		base = location
	}
	return base
}

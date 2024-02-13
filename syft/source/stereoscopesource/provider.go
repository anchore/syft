package stereoscopesource

import (
	"context"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/tagged"
	"github.com/anchore/syft/syft/source"
)

const ImageTag = "image"

type ProviderConfig struct {
	StereoscopeImageProviderConfig stereoscope.ImageProviderConfig
	Exclude                        source.ExcludeConfig
	Alias                          source.Alias
}

type stereoscopeSourceProvider struct {
	stereoscopeProvider image.Provider
	cfg                 ProviderConfig
}

var _ source.Provider = (*stereoscopeSourceProvider)(nil)

func (l stereoscopeSourceProvider) Name() string {
	return l.stereoscopeProvider.Name()
}

func (l stereoscopeSourceProvider) ProvideSource(ctx context.Context) (source.Source, error) {
	img, err := l.stereoscopeProvider.Provide(ctx)
	if err != nil {
		return nil, err
	}
	cfg := ImageConfig{
		Reference:       l.cfg.StereoscopeImageProviderConfig.UserInput,
		Platform:        l.cfg.StereoscopeImageProviderConfig.Platform,
		RegistryOptions: &l.cfg.StereoscopeImageProviderConfig.Registry,
		Exclude:         l.cfg.Exclude,
		Alias:           l.cfg.Alias,
	}
	if err != nil {
		return nil, err
	}
	return New(img, cfg), nil
}

func Providers(cfg ProviderConfig) []tagged.Value[source.Provider] {
	stereoscopeProviders := tagged.ValueSet[source.Provider]{}
	providers := stereoscope.ImageProviders(cfg.StereoscopeImageProviderConfig)
	for _, provider := range providers {
		var sourceProvider source.Provider = stereoscopeSourceProvider{
			stereoscopeProvider: provider.Value,
			cfg:                 cfg,
		}
		stereoscopeProviders = append(stereoscopeProviders,
			tagged.New(sourceProvider, append([]string{provider.Value.Name(), ImageTag}, provider.Tags...)...))
	}
	return stereoscopeProviders
}

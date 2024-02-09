package stereoscopesource

import (
	"context"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/tagged"
	"github.com/anchore/syft/syft/source"
)

const ImageTag = "image"

type stereoscopeSourceProvider struct {
	stereoscopeProvider image.Provider
	alias               *source.Alias
	cfg                 *ProviderConfig
}

var _ source.Provider = (*stereoscopeSourceProvider)(nil)

func (l stereoscopeSourceProvider) Name() string {
	return l.stereoscopeProvider.Name()
}

func (l stereoscopeSourceProvider) Provide(ctx context.Context, req source.Request) (source.Source, error) {
	img, err := l.stereoscopeProvider.Provide(ctx, req.Input, req.Platform)
	if err != nil {
		return nil, err
	}
	var alias source.Alias
	if !l.alias.IsEmpty() {
		alias = *l.alias
	}
	cfg := ImageConfig{
		Reference:       req.Input,
		Platform:        req.Platform,
		RegistryOptions: l.cfg.RegistryOptions,
		Exclude:         l.cfg.Exclude,
		Alias:           alias,
	}
	if err != nil {
		return nil, err
	}
	return New(img, cfg), nil
}

type ProviderConfig struct {
	RegistryOptions *image.RegistryOptions
	Alias           *source.Alias
	Exclude         source.ExcludeConfig
}

func Providers(cfg ProviderConfig) []tagged.Value[source.Provider] {
	var registry image.RegistryOptions
	if cfg.RegistryOptions != nil {
		registry = *cfg.RegistryOptions
	}
	stereoscopeProviders := tagged.ValueSet[source.Provider]{}
	providers := stereoscope.ImageProviders(stereoscope.ImageProviderConfig{
		Registry: registry,
	})
	for _, provider := range providers {
		var sourceProvider source.Provider = stereoscopeSourceProvider{
			stereoscopeProvider: provider.Value,
			alias:               cfg.Alias,
			cfg:                 &cfg,
		}
		stereoscopeProviders = append(stereoscopeProviders,
			tagged.New(sourceProvider, append([]string{provider.Value.Name(), ImageTag}, provider.Tags...)...))
	}
	return stereoscopeProviders
}

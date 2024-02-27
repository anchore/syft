package syft

import (
	"crypto"
	"fmt"

	"github.com/anchore/go-collections"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/sourceproviders"
)

type GetSourceConfig struct {
	// SourceProviderConfig may optionally be provided to be used when constructing the default set of source providers, unused if All specified
	SourceProviderConfig *sourceproviders.Config

	// Sources is an explicit list of source names to use, in order, to attempt to locate a source
	Sources []string

	// DefaultImagePullSource will cause a particular image pull source to be used as the first pull source, followed by other pull sources
	DefaultImagePullSource string
}

func (c *GetSourceConfig) WithAlias(alias source.Alias) *GetSourceConfig {
	c.SourceProviderConfig = c.SourceProviderConfig.WithAlias(alias)
	return c
}

func (c *GetSourceConfig) WithRegistryOptions(registryOptions *image.RegistryOptions) *GetSourceConfig {
	c.SourceProviderConfig = c.SourceProviderConfig.WithRegistryOptions(registryOptions)
	return c
}

func (c *GetSourceConfig) WithPlatform(platform *image.Platform) *GetSourceConfig {
	c.SourceProviderConfig = c.SourceProviderConfig.WithPlatform(platform)
	return c
}

func (c *GetSourceConfig) WithExcludeConfig(excludeConfig source.ExcludeConfig) *GetSourceConfig {
	c.SourceProviderConfig = c.SourceProviderConfig.WithExcludeConfig(excludeConfig)
	return c
}

func (c *GetSourceConfig) WithDigestAlgorithms(algorithms ...crypto.Hash) *GetSourceConfig {
	c.SourceProviderConfig = c.SourceProviderConfig.WithDigestAlgorithms(algorithms...)
	return c
}

func (c *GetSourceConfig) WithBasePath(basePath string) *GetSourceConfig {
	c.SourceProviderConfig = c.SourceProviderConfig.WithBasePath(basePath)
	return c
}

func (c *GetSourceConfig) WithSources(sources ...string) *GetSourceConfig {
	c.Sources = sources
	return c
}

func (c *GetSourceConfig) WithDefaultImagePullSource(defaultImagePullSource string) *GetSourceConfig {
	c.DefaultImagePullSource = defaultImagePullSource
	return c
}

func (c *GetSourceConfig) getProviders(userInput string) ([]source.Provider, error) {
	providers := collections.TaggedValueSet[source.Provider]{}.Join(sourceproviders.All(userInput, c.SourceProviderConfig)...)

	// if the "default image pull source" is set, we move this as the first pull source
	if c.DefaultImagePullSource != "" {
		base := providers.Remove(sourceproviders.PullTag)
		pull := providers.Select(sourceproviders.PullTag)
		def := pull.Select(c.DefaultImagePullSource)
		if len(def) == 0 {
			return nil, fmt.Errorf("invalid DefaultImagePullSource: %s; available values are: %v", c.DefaultImagePullSource, pull.Tags())
		}
		providers = base.Join(def...).Join(pull...)
	}

	// narrow the sources to those explicitly requested generally by a user
	if len(c.Sources) > 0 {
		// select the explicitly provided sources, in order
		providers = providers.Select(c.Sources...)
	}

	return providers.Values(), nil
}

func DefaultGetSourceConfig() *GetSourceConfig {
	return &GetSourceConfig{
		SourceProviderConfig: sourceproviders.DefaultConfig(),
	}
}

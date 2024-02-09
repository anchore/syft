package syft

import (
	"crypto"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/tagged"
	"github.com/anchore/syft/syft/source"
)

type GetSourceConfig struct {
	// SourceProviderConfig may optionally be provided to be used when constructing the default set of source providers, unused if SourceProviders specified
	SourceProviderConfig SourceProviderConfig

	// Platform is used during the source lookup
	Platform *image.Platform

	// SourceProviders the tagged set of known source.Provider to use, will use Syft's default set if not provided
	SourceProviders tagged.ValueSet[source.Provider]

	// BaseSources is used to restrict the set of sources prior to user-provided
	BaseSources []image.Source

	// FromSource is an explicit list of source names to use, in order, to attempt to locate a source
	FromSource []image.Source

	// DefaultImageSource will cause a particular image pull source to be used as the first pull source, followed by other pull sources
	DefaultImageSource image.Source
}

func (c GetSourceConfig) WithAlias(alias source.Alias) GetSourceConfig {
	c.SourceProviderConfig.Alias = alias
	return c
}

func (c GetSourceConfig) WithRegistryOptions(registryOptions *image.RegistryOptions) GetSourceConfig {
	c.SourceProviderConfig.RegistryOptions = registryOptions
	return c
}

func (c GetSourceConfig) WithPlatform(platform *image.Platform) GetSourceConfig {
	c.Platform = platform
	return c
}

func (c GetSourceConfig) WithExcludeConfig(excludeConfig source.ExcludeConfig) GetSourceConfig {
	c.SourceProviderConfig.Exclude = excludeConfig
	return c
}

func (c GetSourceConfig) WithDigestAlgorithms(algorithms ...crypto.Hash) GetSourceConfig {
	c.SourceProviderConfig.DigestAlgorithms = algorithms
	return c
}

func (c GetSourceConfig) WithBasePath(basePath string) GetSourceConfig {
	c.SourceProviderConfig.BasePath = basePath
	return c
}

func (c GetSourceConfig) WithSourceProviders(providers ...tagged.Value[source.Provider]) GetSourceConfig {
	c.SourceProviders = providers
	return c
}

func (c GetSourceConfig) WithBaseSources(sources ...image.Source) GetSourceConfig {
	c.BaseSources = sources
	return c
}

func (c GetSourceConfig) WithFromSource(sources ...image.Source) GetSourceConfig {
	c.FromSource = sources
	return c
}

func (c GetSourceConfig) WithDefaultImageSource(defaultImageSource image.Source) GetSourceConfig {
	c.DefaultImageSource = defaultImageSource
	return c
}

func DefaultGetSourceConfig() GetSourceConfig {
	return GetSourceConfig{
		SourceProviderConfig: DefaultSourceProviderConfig(),
	}
}

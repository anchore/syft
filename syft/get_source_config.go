package syft

import (
	"crypto"
	"fmt"

	"github.com/anchore/go-collections"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

type GetSourceConfig struct {
	// SourceProviderConfig may optionally be provided to be used when constructing the default set of source providers, unused if SourceProviders specified
	SourceProviderConfig SourceProviderConfig

	// SourceProviders the tagged set of known source.Provider to use, will use Syft's default set if not provided
	SourceProviders []collections.TaggedValue[source.Provider]

	// BaseSources is used to restrict the set of sources prior to user-provided
	BaseSources []string

	// FromSource is an explicit list of source names to use, in order, to attempt to locate a source
	FromSource []string

	// DefaultImageSource will cause a particular image pull source to be used as the first pull source, followed by other pull sources
	DefaultImageSource string
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
	c.SourceProviderConfig.Platform = platform
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

func (c GetSourceConfig) WithSourceProviders(providers ...collections.TaggedValue[source.Provider]) GetSourceConfig {
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

func (c GetSourceConfig) getProviders(userInput string) ([]source.Provider, error) {
	providers := collections.TaggedValueSet[source.Provider]{}.Join(c.SourceProviders...)
	if len(providers) == 0 {
		providers = providers.Join(SourceProviders(userInput, c.SourceProviderConfig)...)
	}

	// narrow the sources to those generally programmatically requested (e.g. only pull sources for attest)
	if len(c.BaseSources) > 0 {
		// select the explicitly provided sources, in order
		providers = providers.Select(c.BaseSources...)
	}

	// if the "default image pull source" is set, we move this as the first pull source
	if c.DefaultImageSource != "" {
		base := providers.Remove("pull")
		pull := providers.Select("pull")
		def := pull.Select(c.DefaultImageSource)
		if len(def) == 0 {
			return nil, fmt.Errorf("invalid DefaultImageSource: %s; available values are: %v", c.DefaultImageSource, pull.Tags())
		}
		providers = base.Join(def...).Join(pull...)
	}

	// narrow the sources to those explicitly requested generally by a user
	if len(c.FromSource) > 0 {
		// select the explicitly provided sources, in order
		providers = providers.Select(c.FromSource...)
	}

	return providers.Values(), nil
}

func DefaultGetSourceConfig() GetSourceConfig {
	return GetSourceConfig{
		SourceProviderConfig: DefaultSourceProviderConfig(),
	}
}

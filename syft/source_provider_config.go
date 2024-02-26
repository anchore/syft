package syft

import (
	"crypto"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

// SourceProviderConfig is the uber-configuration for all Syft source providers
type SourceProviderConfig struct {
	Platform         *image.Platform
	Alias            source.Alias
	RegistryOptions  *image.RegistryOptions
	Exclude          source.ExcludeConfig
	DigestAlgorithms []crypto.Hash
	BasePath         string
}

func (c SourceProviderConfig) WithAlias(alias source.Alias) SourceProviderConfig {
	c.Alias = alias
	return c
}

func (c SourceProviderConfig) WithRegistryOptions(registryOptions *image.RegistryOptions) SourceProviderConfig {
	c.RegistryOptions = registryOptions
	return c
}

func (c SourceProviderConfig) WithPlatform(platform *image.Platform) SourceProviderConfig {
	c.Platform = platform
	return c
}

func (c SourceProviderConfig) WithExcludeConfig(excludeConfig source.ExcludeConfig) SourceProviderConfig {
	c.Exclude = excludeConfig
	return c
}

func (c SourceProviderConfig) WithDigestAlgorithms(algorithms ...crypto.Hash) SourceProviderConfig {
	c.DigestAlgorithms = algorithms
	return c
}

func (c SourceProviderConfig) WithBasePath(basePath string) SourceProviderConfig {
	c.BasePath = basePath
	return c
}

func DefaultSourceProviderConfig() SourceProviderConfig {
	return SourceProviderConfig{
		DigestAlgorithms: []crypto.Hash{
			crypto.SHA256,
		},
	}
}

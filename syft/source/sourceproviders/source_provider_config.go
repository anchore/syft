package sourceproviders

import (
	"crypto"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

// Config is the uber-configuration for all Syft source providers
type Config struct {
	Platform         *image.Platform
	Alias            source.Alias
	RegistryOptions  *image.RegistryOptions
	Exclude          source.ExcludeConfig
	DigestAlgorithms []crypto.Hash
	BasePath         string
}

func (c *Config) WithAlias(alias source.Alias) *Config {
	c.Alias = alias
	return c
}

func (c *Config) WithRegistryOptions(registryOptions *image.RegistryOptions) *Config {
	c.RegistryOptions = registryOptions
	return c
}

func (c *Config) WithPlatform(platform *image.Platform) *Config {
	c.Platform = platform
	return c
}

func (c *Config) WithExcludeConfig(excludeConfig source.ExcludeConfig) *Config {
	c.Exclude = excludeConfig
	return c
}

func (c *Config) WithDigestAlgorithms(algorithms ...crypto.Hash) *Config {
	c.DigestAlgorithms = algorithms
	return c
}

func (c *Config) WithBasePath(basePath string) *Config {
	c.BasePath = basePath
	return c
}

func DefaultConfig() *Config {
	return &Config{
		DigestAlgorithms: []crypto.Hash{
			crypto.SHA256,
		},
	}
}

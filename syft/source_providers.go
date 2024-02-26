package syft

import (
	"github.com/anchore/go-collections"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/anchore/syft/syft/source/filesource"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

// SourceProviders returns all the configured source providers known to syft
func SourceProviders(userInput string, cfg SourceProviderConfig) []collections.TaggedValue[source.Provider] {
	stereoscopeProviders := stereoscopeSourceProviders(userInput, cfg)

	return collections.TaggedValueSet[source.Provider]{}.
		// --from file, dir, oci-archive, etc.
		Join(stereoscopeProviders.Select("file", "dir")...).
		Join(tagProvider(filesource.NewSourceProvider(userInput, cfg.Exclude, cfg.DigestAlgorithms, cfg.Alias), "file")).
		Join(tagProvider(directorysource.NewSourceProvider(userInput, cfg.Exclude, cfg.Alias, cfg.BasePath), "dir")).

		// --from docker, registry, etc.
		Join(stereoscopeProviders.Select("pull")...)
}

func stereoscopeSourceProviders(userInput string, cfg SourceProviderConfig) collections.TaggedValueSet[source.Provider] {
	var registry image.RegistryOptions
	if cfg.RegistryOptions != nil {
		registry = *cfg.RegistryOptions
	}
	stereoscopeProviders := stereoscopesource.Providers(stereoscopesource.ProviderConfig{
		StereoscopeImageProviderConfig: stereoscope.ImageProviderConfig{
			UserInput: userInput,
			Platform:  cfg.Platform,
			Registry:  registry,
		},
		Alias:   cfg.Alias,
		Exclude: cfg.Exclude,
	})
	return stereoscopeProviders
}

func tagProvider(provider source.Provider, tags ...string) collections.TaggedValue[source.Provider] {
	return collections.NewTaggedValue(provider, append([]string{provider.Name()}, tags...)...)
}

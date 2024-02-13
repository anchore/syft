package syft

import (
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/tagged"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/anchore/syft/syft/source/filesource"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

// SourceProviders returns all the configured source providers known to syft
func SourceProviders(cfg SourceProviderConfig) tagged.ValueSet[source.Provider] {
	stereoscopeProviders := stereoscopeSourceProviders(cfg)

	return tagged.ValueSet[source.Provider]{}.
		// --from file, dir, oci-archive, etc.
		Join(stereoscopeProviders.Select("file", "dir")...).
		Join(provider(filesource.NewSourceProvider(cfg.UserInput, cfg.Exclude, cfg.DigestAlgorithms, cfg.Alias), "file")).
		Join(provider(directorysource.NewSourceProvider(cfg.UserInput, cfg.Exclude, cfg.Alias, cfg.BasePath), "dir")).

		// --from docker, registry, etc.
		Join(stereoscopeProviders.Select("pull")...)
}

func stereoscopeSourceProviders(cfg SourceProviderConfig) tagged.ValueSet[source.Provider] {
	var registry image.RegistryOptions
	if cfg.RegistryOptions != nil {
		registry = *cfg.RegistryOptions
	}
	stereoscopeProviders := stereoscopesource.Providers(stereoscopesource.ProviderConfig{
		StereoscopeImageProviderConfig: stereoscope.ImageProviderConfig{
			UserInput: cfg.UserInput,
			Platform:  cfg.Platform,
			Registry:  registry,
		},
		Alias:   cfg.Alias,
		Exclude: cfg.Exclude,
	})
	return stereoscopeProviders
}

func provider(provider source.Provider, tags ...string) tagged.Value[source.Provider] {
	return tagged.New(provider, append([]string{provider.Name()}, tags...)...)
}

package syft

import (
	"fmt"

	"github.com/anchore/stereoscope/tagged"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directory"
	"github.com/anchore/syft/syft/source/filesource"
	"github.com/anchore/syft/syft/source/stereoscope"
)

// SourceProviders returns all the configured source providers known to syft
func SourceProviders(sourceProviderConfig ...SourceProviderConfig) tagged.Values[source.Provider] {
	cfg, stereoscopeProviders := stereoscopeSourceProviders(sourceProviderConfig...)

	return tagged.Values[source.Provider]{}.
		// --from file, dir, oci-archive, etc.
		Join(stereoscopeProviders.Select("file", "dir")...).
		Join(provider(filesource.NewSourceProvider(cfg.Exclude, cfg.DigestAlgorithms, cfg.Alias), "file")).
		Join(provider(directory.NewSourceProvider(cfg.Exclude, cfg.Alias, cfg.BasePath), "dir")).

		// --from docker, registry, etc.
		Join(stereoscopeProviders.Select("pull")...)
}

func stereoscopeSourceProviders(sourceProviderConfig ...SourceProviderConfig) (SourceProviderConfig, tagged.Values[source.Provider]) {
	cfg := DefaultSourceProviderConfig()
	if len(sourceProviderConfig) > 1 {
		panic(fmt.Sprintf("at most one sourceProviderConfig may be specified, got %v", sourceProviderConfig))
	}
	if len(sourceProviderConfig) == 1 {
		in := sourceProviderConfig[0]
		if in.RegistryOptions != nil {
			cfg.RegistryOptions = in.RegistryOptions
		}
		if in.Platform != nil {
			cfg.Platform = in.Platform
		}
	}
	stereoscopeProviders := stereoscope.SourceProviders(stereoscope.SourceProviderConfig{
		RegistryOptions: cfg.RegistryOptions,
		Platform:        cfg.Platform,
		Alias:           &cfg.Alias,
		Exclude:         cfg.Exclude,
	})
	return cfg, stereoscopeProviders
}

func provider(provider source.Provider, tags ...string) tagged.Value[source.Provider] {
	return tagged.New(provider, append([]string{provider.Name()}, tags...)...)
}

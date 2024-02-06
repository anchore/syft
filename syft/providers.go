package syft

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/tagged"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directory"
	"github.com/anchore/syft/syft/source/file"
	"github.com/anchore/syft/syft/source/stereoscope"
)

// SourceProviderConfig contains all the source provider configuration known to Syft
type SourceProviderConfig struct {
	Alias            source.Alias
	RegistryOptions  *image.RegistryOptions
	Platform         *image.Platform
	Exclude          source.ExcludeConfig
	DigestAlgorithms []crypto.Hash
	BasePath         string
}

func DefaultSourceProviderConfig() SourceProviderConfig {
	return SourceProviderConfig{
		DigestAlgorithms: []crypto.Hash{
			crypto.SHA256,
		},
	}
}

func GetSource(ctx context.Context, userInput string, providers ...source.Provider) (source.Source, error) {
	if len(providers) == 0 {
		providers = SourceProviders(DefaultSourceProviderConfig()).Collect()
	}

	var errs []error
	for _, p := range providers {
		src, err := p.Provide(ctx, userInput)
		if err != nil {
			errs = append(errs, err)
		}
		if src != nil {
			// if we have a non-image type and platform is specified, it's an error
			//if _, ok := src.(*stereoscope.StereoscopeImageSource); !ok && cfg.Platform != nil {
			//	return src, fmt.Errorf("invalid argument: --platform specified with non-image source")
			//}
			return src, nil
		}
	}

	// TODO better error processing
	return nil, fmt.Errorf("unable to detect source for input: %s %w", userInput, errors.Join(errs...))
}

func SourceProviders(cfg SourceProviderConfig) tagged.Values[source.Provider] {
	stereoscopeProviders := stereoscope.SourceProviders(stereoscope.SourceProviderConfig{
		RegistryOptions: cfg.RegistryOptions,
		Platform:        cfg.Platform,
	})

	return tagged.Values[source.Provider]{}.
		// --from file, dir, oci-archive, etc.
		Join(stereoscopeProviders.Select("file", "dir")...).
		Join(provider(file.NewSourceProvider(cfg.Exclude, cfg.DigestAlgorithms, cfg.Alias), "file")).
		Join(provider(directory.NewSourceProvider(cfg.Exclude, cfg.Alias, cfg.BasePath), "dir")).

		// --from docker,registry,etc.
		Join(stereoscopeProviders.Select("pull")...).

		// any other detectors not tagged with file, dir, or pull
		Join(stereoscopeProviders.Remove("file", "dir", "pull")...)
}

func provider(provider source.Provider, tags ...string) tagged.Value[source.Provider] {
	return tagged.New(provider, append([]string{provider.Name()}, tags...)...)
}

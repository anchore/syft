package syft

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/go-collections"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/sourceproviders"
)

// GetSource uses all of Syft's known source providers to attempt to resolve the user input to a usable source.Source
func GetSource(ctx context.Context, userInput string, cfg *GetSourceConfig) (source.Source, error) {
	if cfg == nil {
		cfg = DefaultGetSourceConfig()
	}

	providers, err := getProviders(userInput, cfg)
	if err != nil {
		return nil, err
	}

	var errs []error
	var fileNotFoundProviders []string

	// call each source provider until we find a valid source
	for _, p := range providers {
		src, err := p.Provide(ctx)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fileNotFoundProviders = append(fileNotFoundProviders, p.Name())
			} else {
				errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
			}
		}
		if err := validateSourcePlatform(src, cfg); err != nil {
			return nil, err
		}
		if src != nil {
			return src, nil
		}
	}

	if len(errs) == 0 {
		return nil, fmt.Errorf("no source providers were able to resolve the input %q", userInput)
	}

	if len(fileNotFoundProviders) > 0 {
		errs = append(errs, fmt.Errorf("additionally, the following providers failed with %w: %s", os.ErrNotExist, strings.Join(fileNotFoundProviders, ", ")))
	}

	return nil, sourceError(userInput, errs...)
}

func getProviders(userInput string, cfg *GetSourceConfig) ([]source.Provider, error) {
	allSourceProviders := sourceproviders.All(userInput, cfg.SourceProviderConfig)
	providers := collections.TaggedValueSet[source.Provider]{}.Join(allSourceProviders...)

	// if the "default image pull source" is set, we move this as the first pull source
	if cfg.DefaultImagePullSource != "" {
		base := providers.Remove(sourceproviders.PullTag)
		pull := providers.Select(sourceproviders.PullTag)
		def := pull.Select(cfg.DefaultImagePullSource)
		if len(def) == 0 {
			return nil, fmt.Errorf("invalid DefaultImagePullSource: %s; available values are: %v", cfg.DefaultImagePullSource, pull.Tags())
		}

		pullWithoutDef := pull.Remove(cfg.DefaultImagePullSource)
		providers = base.Join(def...).Join(pullWithoutDef...)
	}

	// narrow the sources to those explicitly requested generally by a user
	if len(cfg.Sources) > 0 {
		// select the explicitly provided sources, in order
		providers = providers.Select(cfg.Sources...)
	}

	return providers.Values(), nil
}

func validateSourcePlatform(src source.Source, cfg *GetSourceConfig) error {
	if src == nil {
		return nil
	}
	if cfg == nil || cfg.SourceProviderConfig == nil || cfg.SourceProviderConfig.Platform == nil {
		return nil
	}

	meta := src.Describe().Metadata
	switch meta.(type) {
	case *source.ImageMetadata, source.ImageMetadata:
		return nil
	case *source.SnapMetadata, source.SnapMetadata:
		return nil
	default:
		return fmt.Errorf("platform is not supported for this source type")
	}
}

func sourceError(userInput string, errs ...error) error {
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("an error occurred attempting to resolve '%s': %w", userInput, errs[0])
	}
	errorTexts := ""
	for _, e := range errs {
		errorTexts += fmt.Sprintf("\n  - %s", e)
	}
	return fmt.Errorf("errors occurred attempting to resolve '%s':%s", userInput, errorTexts)
}

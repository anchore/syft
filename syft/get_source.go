package syft

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
)

// GetSource uses all of Syft's known source providers to attempt to resolve the user input to a usable source.Source
func GetSource(ctx context.Context, userInput string, cfg *GetSourceConfig) (source.Source, error) {
	if cfg == nil {
		cfg = DefaultGetSourceConfig()
	}

	providers, err := cfg.getProviders(userInput)
	if err != nil {
		return nil, err
	}

	var errs []error
	var fileNotFoundProviders []string

	// call each source provider until we find a valid source
	for _, p := range providers {
		log.WithFields("provider", p.Name(), "ref", userInput).Trace("attempting to resolve source")
		src, err := p.Provide(ctx)
		if err != nil {
			var stopErr *image.ErrFetchingImage
			switch {
			case errors.As(err, &stopErr):
				log.WithFields("provider", p.Name(), "ref", userInput).Trace("resolved but failed to fetch source")
				return nil, sourceError(userInput, err)

			case errors.Is(err, os.ErrNotExist):
				log.WithFields("provider", p.Name(), "ref", userInput).Trace("does not exist")
				fileNotFoundProviders = append(fileNotFoundProviders, p.Name())

			default:
				log.WithFields("provider", p.Name(), "ref", userInput).Trace("failure")
				errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
			}
		}
		log.WithFields("provider", p.Name(), "ref", userInput).Debug("resolved source")
		if src != nil {
			// if we have a non-image type and platform is specified, it's an error
			if cfg.SourceProviderConfig.Platform != nil {
				meta := src.Describe().Metadata
				switch meta.(type) {
				case *source.ImageMetadata, source.ImageMetadata:
				default:
					return src, fmt.Errorf("platform specified with non-image source")
				}
			}
			return src, nil
		}
	}

	if len(fileNotFoundProviders) > 0 {
		errs = append(errs, fmt.Errorf("additionally, the following providers failed with %w: %s", os.ErrNotExist, strings.Join(fileNotFoundProviders, ", ")))
	}
	return nil, sourceError(userInput, errs...)
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

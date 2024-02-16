package syft

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/anchore/syft/syft/source"
)

func GetSource(ctx context.Context, userInput string, getSourceConfig ...GetSourceConfig) (source.Source, error) {
	cfg := DefaultGetSourceConfig()
	if len(getSourceConfig) > 1 {
		return nil, fmt.Errorf("the optional GetSourceConfig requires a single value; got multiple: %v", getSourceConfig)
	}
	if len(getSourceConfig) == 1 {
		cfg = getSourceConfig[0]
	}

	// must set userInput before getting source providers, it is important configuration for them all
	cfg.SourceProviderConfig.UserInput = userInput

	providers, err := cfg.GetProviders()
	if err != nil {
		return nil, err
	}

	var errs []error
	var fileNotfound error

	// call each source provider until we find a valid source
	for _, p := range providers {
		src, err := p.Provide(ctx)
		if err != nil {
			err = eachError(err, func(err error) error {
				if errors.Is(err, os.ErrNotExist) {
					fileNotfound = err
					return nil
				}
				return err
			})
			if err != nil {
				errs = append(errs, err)
			}
		}
		if src != nil {
			// if we have a non-image type and platform is specified, it's an error
			// if _, ok := src.(*stereoscope.StereoscopeImageSource); !ok && cfg.Platform != nil {
			//	return src, fmt.Errorf("invalid argument: --platform specified with non-image source")
			//}
			return src, nil
		}
	}

	if fileNotfound != nil {
		errs = append([]error{fileNotfound}, errs...)
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

func eachError(err error, fn func(error) error) error {
	out := fn(err)
	// unwrap singly wrapped errors
	if e, ok := err.(interface {
		Unwrap() error
	}); ok {
		wrapped := e.Unwrap()
		got := eachError(wrapped, fn)
		// return the outer error if received the same wrapped error
		if errors.Is(got, wrapped) {
			return err
		}
		return got
	}
	// unwrap errors from errors.Join
	if errs, ok := err.(interface {
		Unwrap() []error
	}); ok {
		for _, e := range errs.Unwrap() {
			e = eachError(e, fn)
			if e != nil {
				out = errors.Join(out, e)
			}
		}
	}
	return out
}

package commands

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/go-logger"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func LibInitLoggingConfig(logWrapper logger.Logger) {
	syft.SetLogger(logWrapper)
	stereoscope.SetLogger(logWrapper)
}

func DefaultPackagesOptions() *packagesOptions {
	return defaultPackagesOptions()
}

type PackagesOptions packagesOptions

func GetSource(opts *options.Catalog, userInput string, filters ...func(*source.Detection) error) (source.Source, error) {
	return getSource(opts, userInput, filters...)
}

func LibPackagesExec(id clio.Identification, opts *PackagesOptions, userInput string, l logger.Logger, enable_log bool) (*sbom.SBOM, error) {
	if enable_log {
		LibInitLoggingConfig(l)
	}

	src, err := getSource(&opts.Catalog, userInput)

	if err != nil {
		return nil, err
	}

	defer func() {
		if src != nil {
			if err := src.Close(); err != nil {
				log.Tracef("unable to close source: %+v", err)
			}
		}
	}()

	s, err := generateSBOM(id, src, &opts.Catalog)
	if err != nil {
		return nil, err
	}

	if s == nil {
		return nil, fmt.Errorf("no SBOM produced for %q", userInput)
	}

	return s, nil

}

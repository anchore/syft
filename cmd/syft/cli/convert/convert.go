package convert

import (
	"context"
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/wagoodman/go-partybus"
)

func Run(ctx context.Context, app *config.Application, args []string) error {
	log.Warn("convert is an experimental feature, run `syft convert -h` for help")
	writer, err := options.MakeWriter(app.Outputs, app.File)
	if err != nil {
		return err
	}

	defer func() {
		if err := writer.Close(); err != nil {
			log.Warnf("unable to write to report destination: %w", err)
		}
	}()

	// this can only be a SBOM file
	userInput := args[0]
	f, err := os.Open(userInput)
	if err != nil {
		return fmt.Errorf("failed to open SBOM file: %w", err)
	}
	defer f.Close()

	sbom, _, err := syft.Decode(f)
	if err != nil {
		return fmt.Errorf("failed to decode SBOM: %w", err)
	}
	eventBus := partybus.NewBus()
	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	sub := eventBus.Subscribe()
	// defer sub.Unsubscribe()

	return eventloop.EventLoop(
		func() <-chan error {
			errs := make(chan error)

			go func() {
				defer close(errs)
				if err := writer.Write(*sbom); err != nil {
					errs <- err
				}
			}()
			return errs
		}(),
		eventloop.SetupSignals(),
		sub,
		stereoscope.Cleanup,
		ui.Select(options.IsVerbose(app), app.Quiet)...,
	)
}

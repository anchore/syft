package attest

import (
	"context"
	"fmt"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/cmd/syft/cli/packages"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/formats/cyclonedxjson"
	"github.com/anchore/syft/syft/formats/spdxjson"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

var (
	allowedAttestFormats = []sbom.FormatID{
		syftjson.ID,
		spdxjson.ID,
		cyclonedxjson.ID,
	}

	intotoJSONDsseType = `application/vnd.in-toto+json`
)

func Run(ctx context.Context, app *config.Application, args []string) error {
	// We cannot generate an attestation for more than one output
	if len(app.Outputs) > 1 {
		return fmt.Errorf("unable to generate attestation for more than one output")
	}

	// can only be an image for attestation or OCI DIR
	userInput := args[0]
	si, err := parseImageSource(userInput, app)
	if err != nil {
		return err
	}

	format := formats.ByID(syft.JSONFormatID)

	eventBus := partybus.NewBus()
	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	subscription := eventBus.Subscribe()

	return eventloop.EventLoop(
		execWorker(app, *si, format),
		eventloop.SetupSignals(),
		subscription,
		stereoscope.Cleanup,
		ui.Select(options.IsVerbose(app), app.Quiet)...,
	)
}

func parseAttestationOutput(outputs []string) (format string) {
	if len(outputs) == 0 {
		outputs = append(outputs, string(syftjson.ID))
	}

	return outputs[0]
}

func parseImageSource(userInput string, app *config.Application) (s *source.Input, err error) {
	si, err := source.ParseInputWithName(userInput, app.Platform, false, app.Name)
	if err != nil {
		return nil, fmt.Errorf("could not generate source input for attest command: %w", err)
	}

	switch si.Scheme {
	case source.ImageScheme, source.UnknownScheme:
		// at this point we know that it cannot be dir: or file: schemes;
		// we will assume that the unknown scheme could represent an image;
		si.Scheme = source.ImageScheme
	default:
		return nil, fmt.Errorf("attest command can only be used with image sources but discovered %q when given %q", si.Scheme, userInput)
	}

	// if the original detection was from the local daemon we want to short circuit
	// that and attempt to generate the image source from its current registry source instead
	switch si.ImageSource {
	case image.UnknownSource, image.OciRegistrySource:
		si.ImageSource = image.OciRegistrySource
	case image.SingularitySource:
	default:
		return nil, fmt.Errorf("attest command can only be used with image sources fetch directly from the registry, but discovered an image source of %q when given %q", si.ImageSource, userInput)
	}

	return si, nil
}

func execWorker(app *config.Application, sourceInput source.Input, format sbom.Format) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		src, cleanup, err := source.NewFromRegistry(sourceInput, app.Registry.ToOptions(), app.Exclusions)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			errs <- fmt.Errorf("failed to construct source from user input %q: %w", sourceInput.UserInput, err)
			return
		}

		s, err := packages.GenerateSBOM(src, errs, app)
		if err != nil {
			errs <- err
			return
		}

		_, err = syft.Encode(*s, format)
		if err != nil {
			errs <- err
			return
		}

		// TODO: SHELL OUT HERE

		bus.Publish(partybus.Event{
			Type: event.Exit,
			Value: func() error {
				return nil
			},
		})
	}()
	return errs
}

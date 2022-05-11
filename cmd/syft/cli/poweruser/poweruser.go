package poweruser

import (
	"context"
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/cmd/syft/cli/packages"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"
)

func Run(ctx context.Context, app *config.Application, args []string) error {
	writer, err := sbom.NewWriter(sbom.WriterOption{
		Format: syftjson.Format(),
		Path:   app.File,
	})
	if err != nil {
		return err
	}

	defer func() {
		if err := writer.Close(); err != nil {
			log.Warnf("unable to write to report destination: %+v", err)
		}

		// inform user at end of run that command will be removed
		deprecated := color.Style{color.Red, color.OpBold}.Sprint("DEPRECATED: This command will be removed in v1.0.0")
		fmt.Fprintln(os.Stderr, deprecated)
	}()

	userInput := args[0]
	si, err := source.ParseInput(userInput, app.Platform, true)
	if err != nil {
		return fmt.Errorf("could not generate source input for packages command: %w", err)
	}

	eventBus := partybus.NewBus()
	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	subscription := eventBus.Subscribe()

	return eventloop.EventLoop(
		execWorker(app, *si, writer),
		eventloop.SetupSignals(),
		subscription,
		stereoscope.Cleanup,
		ui.Select(options.IsVerbose(app), app.Quiet)...,
	)
}

func execWorker(app *config.Application, si source.Input, writer sbom.Writer) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		app.Secrets.Cataloger.Enabled = true
		app.FileMetadata.Cataloger.Enabled = true
		app.FileContents.Cataloger.Enabled = true
		app.FileClassification.Cataloger.Enabled = true
		tasks, err := eventloop.Tasks(app)
		if err != nil {
			errs <- err
			return
		}

		src, cleanup, err := source.New(si, app.Registry.ToOptions(), app.Exclusions)
		if err != nil {
			errs <- err
			return
		}
		if cleanup != nil {
			defer cleanup()
		}

		s := sbom.SBOM{
			Source: src.Metadata,
			Descriptor: sbom.Descriptor{
				Name:          internal.ApplicationName,
				Version:       version.FromBuild().Version,
				Configuration: app,
			},
		}

		var relationships []<-chan artifact.Relationship
		for _, task := range tasks {
			c := make(chan artifact.Relationship)
			relationships = append(relationships, c)

			go eventloop.RunTask(task, &s.Artifacts, src, c, errs)
		}

		s.Relationships = append(s.Relationships, packages.MergeRelationships(relationships...)...)

		bus.Publish(partybus.Event{
			Type:  event.Exit,
			Value: func() error { return writer.Write(s) },
		})
	}()

	return errs
}

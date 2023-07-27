package poweruser

import (
	"context"
	"fmt"
	"os"

	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/cmd/syft/cli/packages"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Run(_ context.Context, app *config.Application, args []string) error {
	f := syftjson.Format()
	writer, err := options.MakeSBOMWriterForFormat(f, app.File)
	if err != nil {
		return err
	}
	defer func() {
		// inform user at end of run that command will be removed
		deprecated := color.Style{color.Red, color.OpBold}.Sprint("DEPRECATED: This command will be removed in v1.0.0")
		fmt.Fprintln(os.Stderr, deprecated)
	}()

	userInput := args[0]

	eventBus := partybus.NewBus()
	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	subscription := eventBus.Subscribe()

	return eventloop.EventLoop(
		execWorker(app, userInput, writer),
		eventloop.SetupSignals(),
		subscription,
		stereoscope.Cleanup,
		ui.Select(options.IsVerbose(app), app.Quiet)...,
	)
}

//nolint:funlen
func execWorker(app *config.Application, userInput string, writer sbom.Writer) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		defer bus.Exit()

		app.Secrets.Cataloger.Enabled = true
		app.FileMetadata.Cataloger.Enabled = true
		app.FileContents.Cataloger.Enabled = true
		app.FileClassification.Cataloger.Enabled = true
		tasks, err := eventloop.Tasks(app)
		if err != nil {
			errs <- err
			return
		}

		detection, err := source.Detect(
			userInput,
			source.DetectConfig{
				DefaultImageSource: app.DefaultImagePullSource,
			},
		)
		if err != nil {
			errs <- fmt.Errorf("could not deteremine source: %w", err)
			return
		}

		var platform *image.Platform

		if app.Platform != "" {
			platform, err = image.NewPlatform(app.Platform)
			if err != nil {
				errs <- fmt.Errorf("invalid platform: %w", err)
				return
			}
		}

		src, err := detection.NewSource(
			source.DetectionSourceConfig{
				Alias: source.Alias{
					Name:    app.Source.Name,
					Version: app.Source.Version,
				},
				RegistryOptions: app.Registry.ToOptions(),
				Platform:        platform,
				Exclude: source.ExcludeConfig{
					Paths: app.Exclusions,
				},
				DigestAlgorithms: nil,
				BasePath:         app.BasePath,
			},
		)

		if src != nil {
			defer src.Close()
		}
		if err != nil {
			errs <- fmt.Errorf("failed to construct source from user input %q: %w", userInput, err)
			return
		}

		s := sbom.SBOM{
			Source: src.Describe(),
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

		if err := writer.Write(s); err != nil {
			errs <- fmt.Errorf("failed to write sbom: %w", err)
			return
		}
	}()

	return errs
}

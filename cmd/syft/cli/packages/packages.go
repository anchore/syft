package packages

import (
	"context"
	"fmt"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Run(_ context.Context, app *config.Application, args []string) error {
	err := ValidateOutputOptions(app)
	if err != nil {
		return err
	}

	writer, err := options.MakeSBOMWriter(app.Outputs, app.File, app.OutputTemplatePath)
	if err != nil {
		return err
	}

	// could be an image or a directory, with or without a scheme
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

// nolint:funlen
func execWorker(app *config.Application, userInput string, writer sbom.Writer) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		defer bus.Exit()

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

		hashers, err := file.Hashers(app.Source.File.Digests...)
		if err != nil {
			errs <- fmt.Errorf("invalid hash: %w", err)
			return
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
				DigestAlgorithms: hashers,
				BasePath:         app.BasePath,
			},
		)

		if err != nil {
			errs <- fmt.Errorf("failed to construct source from user input %q: %w", userInput, err)
			return
		}

		defer func() {
			if src != nil {
				if err := src.Close(); err != nil {
					log.Tracef("unable to close source: %+v", err)
				}
			}
		}()

		s, err := GenerateSBOM(src, errs, app)
		if err != nil {
			errs <- err
			return
		}

		if s == nil {
			errs <- fmt.Errorf("no SBOM produced for %q", userInput)
			return
		}

		if err := writer.Write(*s); err != nil {
			errs <- fmt.Errorf("failed to write SBOM: %w", err)
			return
		}
	}()
	return errs
}

func GenerateSBOM(src source.Source, errs chan error, app *config.Application) (*sbom.SBOM, error) {
	tasks, err := eventloop.Tasks(app)
	if err != nil {
		return nil, err
	}

	s := sbom.SBOM{
		Source: src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:          internal.ApplicationName,
			Version:       version.FromBuild().Version,
			Configuration: app,
		},
	}

	buildRelationships(&s, src, tasks, errs)

	return &s, nil
}

func buildRelationships(s *sbom.SBOM, src source.Source, tasks []eventloop.Task, errs chan error) {
	var relationships []<-chan artifact.Relationship
	for _, task := range tasks {
		c := make(chan artifact.Relationship)
		relationships = append(relationships, c)
		go eventloop.RunTask(task, &s.Artifacts, src, c, errs)
	}

	s.Relationships = append(s.Relationships, MergeRelationships(relationships...)...)
}

func MergeRelationships(cs ...<-chan artifact.Relationship) (relationships []artifact.Relationship) {
	for _, c := range cs {
		for n := range c {
			relationships = append(relationships, n)
		}
	}

	return relationships
}

func ValidateOutputOptions(app *config.Application) error {
	var usesTemplateOutput bool
	for _, o := range app.Outputs {
		if o == template.ID.String() {
			usesTemplateOutput = true
			break
		}
	}

	if usesTemplateOutput && app.OutputTemplatePath == "" {
		return fmt.Errorf(`must specify path to template file when using "template" output format`)
	}

	return nil
}

package packages

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/anchore"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Run(ctx context.Context, app *config.Application, args []string) error {
	err := validateOutputOptions(app)
	if err != nil {
		return err
	}

	writer, err := options.MakeWriter(app.Outputs, app.File, app.OutputTemplatePath)
	if err != nil {
		return err
	}

	defer func() {
		if err := writer.Close(); err != nil {
			log.Warnf("unable to write to report destination: %w", err)
		}
	}()

	// TODO support input from config somehow
	var userInputs []source.Input
	for _, userInput := range args {
		// could be an image or a directory, with or without a scheme
		si, err := source.ParseInput(userInput, app.Platform, true)
		if err != nil {
			return fmt.Errorf("could not generate source input for packages command: %w", err)
		}
		userInputs = append(userInputs, *si)
	}

	eventBus := partybus.NewBus()
	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	subscription := eventBus.Subscribe()

	return eventloop.EventLoop(
		execWorker(app, userInputs, writer),
		eventloop.SetupSignals(),
		subscription,
		stereoscope.Cleanup,
		ui.Select(options.IsVerbose(app), app.Quiet)...,
	)
}

func execWorker(app *config.Application, input []source.Input, writer sbom.Writer) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		var sources []source.Source
		for _, si := range input {
			src, cleanup, err := source.New(si, app.Registry.ToOptions(), app.Exclusions)
			if cleanup != nil {
				defer cleanup()
			}
			if err != nil {
				errs <- fmt.Errorf("failed to construct source from user input %q: %w", si.UserInput, err)
				return
			}
			sources = append(sources, *src)
		}

		s, err := GenerateSBOM(sources, errs, app)
		if err != nil {
			errs <- err
			return
		}

		if s == nil {
			userInput := ""
			for i, in := range input {
				if i > 0 {
					userInput += " "
				}
				userInput += in.UserInput
			}
			errs <- fmt.Errorf("no SBOM produced for %q", userInput)
		}

		if app.Anchore.Host != "" {
			// FIXME
			if err := runPackageSbomUpload(&sources[0], *s, app); err != nil {
				errs <- err
				return
			}
		}

		bus.Publish(partybus.Event{
			Type:  event.Exit,
			Value: func() error { return writer.Write(*s) },
		})
	}()
	return errs
}

func GenerateSBOM(sources []source.Source, errs chan error, app *config.Application) (*sbom.SBOM, error) {
	tasks, err := eventloop.Tasks(app)
	if err != nil {
		return nil, err
	}

	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog:      pkg.NewCatalog(),
			Secrets:             map[source.Coordinates][]file.SearchResult{},
			FileDigests:         map[source.Coordinates][]file.Digest{},
			FileClassifications: map[source.Coordinates][]file.Classification{},
			FileMetadata:        map[source.Coordinates]source.FileMetadata{},
			FileContents:        map[source.Coordinates]string{},
		},
		Descriptor: sbom.Descriptor{
			Name:          internal.ApplicationName,
			Version:       version.FromBuild().Version,
			Configuration: app,
		},
	}

	buildSBOM(&s, sources, tasks, errs)

	return &s, nil
}

func buildSBOM(s *sbom.SBOM, sources []source.Source, tasks []eventloop.Task, errs chan error) {
	for _, src := range sources {
		src := src
		meta := &src.Metadata
		s.Sources = append(s.Sources, *meta)
		for _, task := range tasks {
			eventloop.RunTask(task, s, &src, errs)
		}
	}
}

func runPackageSbomUpload(src *source.Source, s sbom.SBOM, app *config.Application) error {
	log.Infof("uploading results to %s", app.Anchore.Host)

	if src.Metadata.Scheme != source.ImageScheme {
		return fmt.Errorf("unable to upload results: only images are supported")
	}

	var dockerfileContents []byte
	if app.Anchore.Dockerfile != "" {
		if _, err := os.Stat(app.Anchore.Dockerfile); os.IsNotExist(err) {
			return fmt.Errorf("unable dockerfile=%q does not exist: %w", app.Anchore.Dockerfile, err)
		}

		fh, err := os.Open(app.Anchore.Dockerfile)
		if err != nil {
			return fmt.Errorf("unable to open dockerfile=%q: %w", app.Anchore.Dockerfile, err)
		}

		dockerfileContents, err = io.ReadAll(fh)
		if err != nil {
			return fmt.Errorf("unable to read dockerfile=%q: %w", app.Anchore.Dockerfile, err)
		}
	}

	c, err := anchore.NewClient(anchore.Configuration{
		BaseURL:  app.Anchore.Host,
		Username: app.Anchore.Username,
		Password: app.Anchore.Password,
	})

	if err != nil {
		return fmt.Errorf("failed to create anchore client: %w", err)
	}

	importCfg := anchore.ImportConfig{
		ImageMetadata:           src.Image.Metadata,
		SBOM:                    s,
		Dockerfile:              dockerfileContents,
		OverwriteExistingUpload: app.Anchore.OverwriteExistingImage,
		Timeout:                 app.Anchore.ImportTimeout,
	}

	if err := c.Import(context.Background(), importCfg); err != nil {
		return fmt.Errorf("failed to upload results to host=%s: %+v", app.Anchore.Host, err)
	}

	return nil
}

func validateOutputOptions(app *config.Application) error {
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

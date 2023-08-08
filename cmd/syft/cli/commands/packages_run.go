package commands

import (
	"fmt"

	"github.com/hashicorp/go-multierror"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// nolint:funlen
func runPackages(app clio.Application, opts *packagesOptions, userInput string) error {
	err := validatePackageOutputOptions(&opts.Output)
	if err != nil {
		return err
	}

	writer, err := options.MakeSBOMWriter(opts.Outputs, opts.File, opts.OutputTemplatePath)
	if err != nil {
		return err
	}

	defer bus.Exit()

	detection, err := source.Detect(
		userInput,
		source.DetectConfig{
			DefaultImageSource: opts.DefaultImagePullSource,
		},
	)
	if err != nil {
		return fmt.Errorf("could not deteremine source: %w", err)
	}

	var platform *image.Platform

	if opts.Platform != "" {
		platform, err = image.NewPlatform(opts.Platform)
		if err != nil {
			return fmt.Errorf("invalid platform: %w", err)
		}
	}

	hashers, err := file.Hashers(opts.Source.File.Digests...)
	if err != nil {
		return fmt.Errorf("invalid hash: %w", err)
	}

	src, err := detection.NewSource(
		source.DetectionSourceConfig{
			Alias: source.Alias{
				Name:    opts.Source.Name,
				Version: opts.Source.Version,
			},
			RegistryOptions: opts.Registry.ToOptions(),
			Platform:        platform,
			Exclude: source.ExcludeConfig{
				Paths: opts.Exclusions,
			},
			DigestAlgorithms: hashers,
			BasePath:         opts.BasePath,
		},
	)

	if err != nil {
		return fmt.Errorf("failed to construct source from user input %q: %w", userInput, err)
	}

	defer func() {
		if src != nil {
			if err := src.Close(); err != nil {
				log.Tracef("unable to close source: %+v", err)
			}
		}
	}()

	s, err := generateSBOM(app, src, &opts.Packages)
	if err != nil {
		return err
	}

	if s == nil {
		return fmt.Errorf("no SBOM produced for %q", userInput)
	}

	if err := writer.Write(*s); err != nil {
		return fmt.Errorf("failed to write SBOM: %w", err)
	}

	return nil
}

func generateSBOM(app clio.Application, src source.Source, opts *options.Packages) (*sbom.SBOM, error) {
	tasks, err := eventloop.Tasks(opts)
	if err != nil {
		return nil, err
	}

	s := sbom.SBOM{
		Source: src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:          app.ID().Name,
			Version:       app.ID().Version,
			Configuration: opts,
		},
	}

	err = buildRelationships(&s, src, tasks)

	return &s, err
}

func buildRelationships(s *sbom.SBOM, src source.Source, tasks []eventloop.Task) error {
	var errs error

	var relationships []<-chan artifact.Relationship
	for _, task := range tasks {
		c := make(chan artifact.Relationship)
		relationships = append(relationships, c)
		go func(task eventloop.Task) {
			err := eventloop.RunTask(task, &s.Artifacts, src, c)
			if err != nil {
				errs = multierror.Append(errs, err)
			}
		}(task)
	}

	s.Relationships = append(s.Relationships, mergeRelationships(relationships...)...)

	return errs
}

func mergeRelationships(cs ...<-chan artifact.Relationship) (relationships []artifact.Relationship) {
	for _, c := range cs {
		for n := range c {
			relationships = append(relationships, n)
		}
	}

	return relationships
}

func validatePackageOutputOptions(cfg *options.Output) error {
	var usesTemplateOutput bool
	for _, o := range cfg.Outputs {
		if o == template.ID.String() {
			usesTemplateOutput = true
			break
		}
	}

	if usesTemplateOutput && cfg.OutputTemplatePath == "" {
		return fmt.Errorf(`must specify path to template file when using "template" output format`)
	}

	return nil
}

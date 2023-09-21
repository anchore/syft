package commands

import (
	"fmt"
	"os"

	"github.com/gookit/color"
	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const powerUserExample = `  {{.appName}} {{.command}} <image>
  DEPRECATED - THIS COMMAND WILL BE REMOVED in v1.0.0
  Template outputs are not supported.
  All behavior is controlled via application configuration and environment variables (see https://github.com/anchore/syft#configuration)
`

type powerUserOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.OutputFile  `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	options.Catalog     `yaml:",inline" mapstructure:",squash"`
}

func PowerUser(app clio.Application) *cobra.Command {
	id := app.ID()

	pkgs := options.DefaultCatalog()
	pkgs.Secrets.Cataloger.Enabled = true
	pkgs.FileMetadata.Cataloger.Enabled = true
	pkgs.FileContents.Cataloger.Enabled = true
	pkgs.FileClassification.Cataloger.Enabled = true
	opts := &powerUserOptions{
		Catalog: pkgs,
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "power-user [IMAGE]",
		Short: "Run bulk operations on container images",
		Example: internal.Tprintf(powerUserExample, map[string]interface{}{
			"appName": id.Name,
			"command": "power-user",
		}),
		Args:    validatePackagesArgs,
		Hidden:  true,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPowerUser(id, opts, args[0])
		},
	}, opts)
}

//nolint:funlen
func runPowerUser(id clio.Identification, opts *powerUserOptions, userInput string) error {
	writer, err := opts.SBOMWriter(syftjson.Format())
	if err != nil {
		return err
	}
	defer func() {
		// inform user at end of run that command will be removed
		deprecated := color.Style{color.Red, color.OpBold}.Sprint("DEPRECATED: This command will be removed in v1.0.0")
		fmt.Fprintln(os.Stderr, deprecated)
	}()

	tasks, err := eventloop.Tasks(&opts.Catalog)
	if err != nil {
		return err
	}

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
			DigestAlgorithms: nil,
			BasePath:         opts.BasePath,
		},
	)

	if src != nil {
		defer src.Close()
	}
	if err != nil {
		return fmt.Errorf("failed to construct source from user input %q: %w", userInput, err)
	}

	s := sbom.SBOM{
		Source: src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:          id.Name,
			Version:       id.Version,
			Configuration: opts,
		},
	}

	var errs error
	var relationships []<-chan artifact.Relationship
	for _, task := range tasks {
		c := make(chan artifact.Relationship)
		relationships = append(relationships, c)

		go func(task eventloop.Task) {
			err := eventloop.RunTask(task, &s.Artifacts, src, c)
			errs = multierror.Append(errs, err)
		}(task)
	}

	if errs != nil {
		return errs
	}

	s.Relationships = append(s.Relationships, mergeRelationships(relationships...)...)

	if err := writer.Write(s); err != nil {
		return fmt.Errorf("failed to write sbom: %w", err)
	}

	return nil
}

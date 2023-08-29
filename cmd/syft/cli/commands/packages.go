package commands

import (
	"fmt"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const (
	packagesExample = `  {{.appName}} {{.command}} alpine:latest                                a summary of discovered packages
  {{.appName}} {{.command}} alpine:latest -o json                        show all possible cataloging details
  {{.appName}} {{.command}} alpine:latest -o cyclonedx                   show a CycloneDX formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o cyclonedx-json              show a CycloneDX JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx                        show a SPDX 2.3 Tag-Value formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx@2.2                    show a SPDX 2.2 Tag-Value formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx-json                   show a SPDX 2.3 JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx-json@2.2               show a SPDX 2.2 JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -vv                            show verbose debug information
  {{.appName}} {{.command}} alpine:latest -o template -t my_format.tmpl  show a SBOM formatted according to given template file

  Supports the following image sources:
    {{.appName}} {{.command}} yourrepo/yourimage:tag     defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry.
    {{.appName}} {{.command}} path/to/a/file/or/dir      a Docker tar, OCI tar, OCI directory, SIF container, or generic filesystem directory
`

	schemeHelpHeader = "You can also explicitly specify the scheme to use:"
	imageSchemeHelp  = `    {{.appName}} {{.command}} docker:yourrepo/yourimage:tag            explicitly use the Docker daemon
    {{.appName}} {{.command}} podman:yourrepo/yourimage:tag            explicitly use the Podman daemon
    {{.appName}} {{.command}} registry:yourrepo/yourimage:tag          pull image directly from a registry (no container runtime required)
    {{.appName}} {{.command}} docker-archive:path/to/yourimage.tar     use a tarball from disk for archives created from "docker save"
    {{.appName}} {{.command}} oci-archive:path/to/yourimage.tar        use a tarball from disk for OCI archives (from Skopeo or otherwise)
    {{.appName}} {{.command}} oci-dir:path/to/yourimage                read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    {{.appName}} {{.command}} singularity:path/to/yourimage.sif        read directly from a Singularity Image Format (SIF) container on disk
`
	nonImageSchemeHelp = `    {{.appName}} {{.command}} dir:path/to/yourproject                  read directly from a path on disk (any directory)
    {{.appName}} {{.command}} file:path/to/yourproject/file            read directly from a path on disk (any single file)
`
	packagesSchemeHelp = "\n  " + schemeHelpHeader + "\n" + imageSchemeHelp + nonImageSchemeHelp

	packagesHelp = packagesExample + packagesSchemeHelp
)

type packagesOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.MultiOutput `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	options.Catalog     `yaml:",inline" mapstructure:",squash"`
}

func defaultPackagesOptions() *packagesOptions {
	return &packagesOptions{
		MultiOutput: options.DefaultOutput(),
		UpdateCheck: options.DefaultUpdateCheck(),
		Catalog:     options.DefaultCatalog(),
	}
}

//nolint:dupl
func Packages(app clio.Application) *cobra.Command {
	id := app.ID()

	opts := defaultPackagesOptions()

	return app.SetupCommand(&cobra.Command{
		Use:   "packages [SOURCE]",
		Short: "Generate a package SBOM",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from container images and filesystems",
		Example: internal.Tprintf(packagesHelp, map[string]interface{}{
			"appName": id.Name,
			"command": "packages",
		}),
		Args:    validatePackagesArgs,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPackages(id, opts, args[0])
		},
	}, opts)
}

func validatePackagesArgs(cmd *cobra.Command, args []string) error {
	return validateArgs(cmd, args, "an image/directory argument is required")
}

func validateArgs(cmd *cobra.Command, args []string, error string) error {
	if len(args) == 0 {
		// in the case that no arguments are given we want to show the help text and return with a non-0 return code.
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
		return fmt.Errorf(error)
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}

// nolint:funlen
func runPackages(id clio.Identification, opts *packagesOptions, userInput string) error {
	err := validatePackageOutputOptions(&opts.MultiOutput)
	if err != nil {
		return err
	}

	writer, err := opts.SBOMWriter()
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

	s, err := generateSBOM(id, src, &opts.Catalog)
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

func generateSBOM(id clio.Identification, src source.Source, opts *options.Catalog) (*sbom.SBOM, error) {
	tasks, err := eventloop.Tasks(opts)
	if err != nil {
		return nil, err
	}

	s := sbom.SBOM{
		Source: src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:          id.Name,
			Version:       id.Version,
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

func validatePackageOutputOptions(cfg *options.MultiOutput) error {
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

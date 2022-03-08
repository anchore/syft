package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/anchore"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
)

const (
	packagesExample = `  {{.appName}} {{.command}} alpine:latest                    a summary of discovered packages
  {{.appName}} {{.command}} alpine:latest -o json            show all possible cataloging details
  {{.appName}} {{.command}} alpine:latest -o cyclonedx       show a CycloneDX formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o cyclonedx-json  show a CycloneDX JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx            show a SPDX 2.2 Tag-Value formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx-json       show a SPDX 2.2 JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -vv                show verbose debug information

  Supports the following image sources:
    {{.appName}} {{.command}} yourrepo/yourimage:tag     defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry.
    {{.appName}} {{.command}} path/to/a/file/or/dir      a Docker tar, OCI tar, OCI directory, or generic filesystem directory
`

	schemeHelpHeader = "You can also explicitly specify the scheme to use:"
	imageSchemeHelp  = `    {{.appName}} {{.command}} docker:yourrepo/yourimage:tag          explicitly use the Docker daemon
    {{.appName}} {{.command}} podman:yourrepo/yourimage:tag        	 explicitly use the Podman daemon
    {{.appName}} {{.command}} registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
    {{.appName}} {{.command}} docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
    {{.appName}} {{.command}} oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Skopeo or otherwise)
    {{.appName}} {{.command}} oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
`
	nonImageSchemeHelp = `    {{.appName}} {{.command}} dir:path/to/yourproject                read directly from a path on disk (any directory)
    {{.appName}} {{.command}} file:path/to/yourproject/file          read directly from a path on disk (any single file)
`
	packagesSchemeHelp = "\n" + indent + schemeHelpHeader + "\n" + imageSchemeHelp + nonImageSchemeHelp

	packagesHelp = packagesExample + packagesSchemeHelp
)

var (
	packagesCmd = &cobra.Command{
		Use:   "packages [SOURCE]",
		Short: "Generate a package SBOM",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from container images and filesystems",
		Example: internal.Tprintf(packagesHelp, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "packages",
		}),
		Args:          validateInputArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) (err error) {
			if appConfig.Dev.ProfileCPU && appConfig.Dev.ProfileMem {
				return fmt.Errorf("cannot profile CPU and memory simultaneously")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if appConfig.Dev.ProfileCPU {
				defer profile.Start(profile.CPUProfile).Stop()
			} else if appConfig.Dev.ProfileMem {
				defer profile.Start(profile.MemProfile).Stop()
			}

			return packagesExec(cmd, args)
		},
		ValidArgsFunction: dockerImageValidArgsFunction,
	}
)

func init() {
	setPackageFlags(packagesCmd.Flags())

	rootCmd.AddCommand(packagesCmd)
}

func setPackageFlags(flags *pflag.FlagSet) {
	// Formatting & Input options //////////////////////////////////////////////
	flags.StringP(
		"scope", "s", cataloger.DefaultSearchConfig().Scope.String(),
		fmt.Sprintf("selection of layers to catalog, options=%v", source.AllScopes))

	flags.StringArrayP(
		"output", "o", formatAliases(table.ID),
		fmt.Sprintf("report output format, options=%v", formatAliases(syft.FormatIDs()...)),
	)

	flags.StringP(
		"file", "", "",
		"file to write the default report output to (default is STDOUT)",
	)

	flags.StringP(
		"platform", "", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')",
	)

	// Upload options //////////////////////////////////////////////////////////
	flags.StringP(
		"host", "H", "",
		"the hostname or URL of the Anchore Enterprise instance to upload to",
	)

	flags.StringP(
		"username", "u", "",
		"the username to authenticate against Anchore Enterprise",
	)

	flags.StringP(
		"password", "p", "",
		"the password to authenticate against Anchore Enterprise",
	)

	flags.StringP(
		"dockerfile", "d", "",
		"include dockerfile for upload to Anchore Enterprise",
	)

	flags.StringArrayP(
		"exclude", "", nil,
		"exclude paths from being scanned using a glob expression",
	)

	flags.Bool(
		"overwrite-existing-image", false,
		"overwrite an existing image during the upload to Anchore Enterprise",
	)

	flags.Uint(
		"import-timeout", 30,
		"set a timeout duration (in seconds) for the upload to Anchore Enterprise",
	)
}

func bindPackagesConfigOptions(flags *pflag.FlagSet) error {
	if err := bindExclusivePackagesConfigOptions(flags); err != nil {
		return err
	}
	if err := bindSharedConfigOption(flags); err != nil {
		return err
	}
	return nil
}

// NOTE(alex): Write a helper for the binding operation, which can be used to perform the binding but also double check that the intended effect was had or else return an error. Another thought is to somehow provide zero-valued defaults for all values in our config struct (maybe with reflection?). There may be a mechanism that already exists in viper that protects against this that I'm not aware of. ref: https://github.com/anchore/syft/pull/805#discussion_r801931192
func bindExclusivePackagesConfigOptions(flags *pflag.FlagSet) error {
	// Formatting & Input options //////////////////////////////////////////////

	// note: output is not included since this configuration option is shared between multiple subcommands

	if err := viper.BindPFlag("package.cataloger.scope", flags.Lookup("scope")); err != nil {
		return err
	}

	if err := viper.BindPFlag("file", flags.Lookup("file")); err != nil {
		return err
	}

	if err := viper.BindPFlag("exclude", flags.Lookup("exclude")); err != nil {
		return err
	}

	// Upload options //////////////////////////////////////////////////////////

	if err := viper.BindPFlag("anchore.host", flags.Lookup("host")); err != nil {
		return err
	}

	if err := viper.BindPFlag("anchore.username", flags.Lookup("username")); err != nil {
		return err
	}

	if err := viper.BindPFlag("anchore.password", flags.Lookup("password")); err != nil {
		return err
	}

	if err := viper.BindPFlag("anchore.dockerfile", flags.Lookup("dockerfile")); err != nil {
		return err
	}

	if err := viper.BindPFlag("anchore.overwrite-existing-image", flags.Lookup("overwrite-existing-image")); err != nil {
		return err
	}

	if err := viper.BindPFlag("anchore.import-timeout", flags.Lookup("import-timeout")); err != nil {
		return err
	}

	return nil
}

func validateInputArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		// in the case that no arguments are given we want to show the help text and return with a non-0 return code.
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
		return fmt.Errorf("an image/directory argument is required")
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}

func packagesExec(_ *cobra.Command, args []string) error {
	writer, err := makeWriter(appConfig.Outputs, appConfig.File)
	if err != nil {
		return err
	}

	defer func() {
		if err := writer.Close(); err != nil {
			log.Warnf("unable to write to report destination: %w", err)
		}
	}()

	// could be an image or a directory, with or without a scheme
	userInput := args[0]
	si, err := source.ParseInput(userInput, appConfig.Platform, true)
	if err != nil {
		return fmt.Errorf("could not generate source input for packages command: %w", err)
	}

	return eventLoop(
		packagesExecWorker(*si, writer),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet)...,
	)
}

func isVerbose() (result bool) {
	isPipedInput, err := internal.IsPipedInput()
	if err != nil {
		// since we can't tell if there was piped input we assume that there could be to disable the ETUI
		log.Warnf("unable to determine if there is piped input: %+v", err)
		return true
	}
	// verbosity should consider if there is piped input (in which case we should not show the ETUI)
	return appConfig.CliOptions.Verbosity > 0 || isPipedInput
}

func generateSBOM(src *source.Source, errs chan error) (*sbom.SBOM, error) {
	tasks, err := tasks()
	if err != nil {
		return nil, err
	}

	s := sbom.SBOM{
		Source: src.Metadata,
		Descriptor: sbom.Descriptor{
			Name:          internal.ApplicationName,
			Version:       version.FromBuild().Version,
			Configuration: appConfig,
		},
	}

	buildRelationships(&s, src, tasks, errs)

	return &s, nil
}

func buildRelationships(s *sbom.SBOM, src *source.Source, tasks []task, errs chan error) {
	var relationships []<-chan artifact.Relationship
	for _, task := range tasks {
		c := make(chan artifact.Relationship)
		relationships = append(relationships, c)
		go runTask(task, &s.Artifacts, src, c, errs)
	}

	s.Relationships = append(s.Relationships, mergeRelationships(relationships...)...)
}

func packagesExecWorker(si source.Input, writer sbom.Writer) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		src, cleanup, err := source.New(si, appConfig.Registry.ToOptions(), appConfig.Exclusions)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			errs <- fmt.Errorf("failed to construct source from user input %q: %w", si.UserInput, err)
			return
		}

		s, err := generateSBOM(src, errs)
		if err != nil {
			errs <- err
			return
		}

		if s == nil {
			errs <- fmt.Errorf("no SBOM produced for %q", si.UserInput)
		}

		if appConfig.Anchore.Host != "" {
			if err := runPackageSbomUpload(src, *s); err != nil {
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

func mergeRelationships(cs ...<-chan artifact.Relationship) (relationships []artifact.Relationship) {
	for _, c := range cs {
		for n := range c {
			relationships = append(relationships, n)
		}
	}

	return relationships
}

func runPackageSbomUpload(src *source.Source, s sbom.SBOM) error {
	log.Infof("uploading results to %s", appConfig.Anchore.Host)

	if src.Metadata.Scheme != source.ImageScheme {
		return fmt.Errorf("unable to upload results: only images are supported")
	}

	var dockerfileContents []byte
	if appConfig.Anchore.Dockerfile != "" {
		if _, err := os.Stat(appConfig.Anchore.Dockerfile); os.IsNotExist(err) {
			return fmt.Errorf("unable dockerfile=%q does not exist: %w", appConfig.Anchore.Dockerfile, err)
		}

		fh, err := os.Open(appConfig.Anchore.Dockerfile)
		if err != nil {
			return fmt.Errorf("unable to open dockerfile=%q: %w", appConfig.Anchore.Dockerfile, err)
		}

		dockerfileContents, err = ioutil.ReadAll(fh)
		if err != nil {
			return fmt.Errorf("unable to read dockerfile=%q: %w", appConfig.Anchore.Dockerfile, err)
		}
	}

	c, err := anchore.NewClient(anchore.Configuration{
		BaseURL:  appConfig.Anchore.Host,
		Username: appConfig.Anchore.Username,
		Password: appConfig.Anchore.Password,
	})
	if err != nil {
		return fmt.Errorf("failed to create anchore client: %w", err)
	}

	importCfg := anchore.ImportConfig{
		ImageMetadata:           src.Image.Metadata,
		SBOM:                    s,
		Dockerfile:              dockerfileContents,
		OverwriteExistingUpload: appConfig.Anchore.OverwriteExistingImage,
		Timeout:                 appConfig.Anchore.ImportTimeout,
	}

	if err := c.Import(context.Background(), importCfg); err != nil {
		return fmt.Errorf("failed to upload results to host=%s: %+v", appConfig.Anchore.Host, err)
	}

	return nil
}

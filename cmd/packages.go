package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/viper"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/anchore"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/presenter/packages"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wagoodman/go-partybus"
)

const (
	packagesExample = `  {{.appName}} {{.command}} alpine:latest                a summary of discovered packages
  {{.appName}} {{.command}} alpine:latest -o json        show all possible cataloging details
  {{.appName}} {{.command}} alpine:latest -o cyclonedx   show a CycloneDX SBOM
  {{.appName}} {{.command}} alpine:latest -vv            show verbose debug information

  Supports the following image sources:
    {{.appName}} {{.command}} yourrepo/yourimage:tag     defaults to using images from a Docker daemon. If docker is not present, the image is pulled directly from the registry.
    {{.appName}} {{.command}} path/to/a/file/or/dir      a Docker tar, OCI tar, OCI directory, or generic filesystem directory 

  You can also explicitly specify the scheme to use:
    {{.appName}} {{.command}} docker:yourrepo/yourimage:tag          explicitly use the Docker daemon
    {{.appName}} {{.command}} docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
    {{.appName}} {{.command}} oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Skopeo or otherwise)
    {{.appName}} {{.command}} oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    {{.appName}} {{.command}} dir:path/to/yourproject                read directly from a path on disk (any directory)
    {{.appName}} {{.command}} registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
`
)

var (
	packagesPresenterOpt packages.PresenterOption
	packagesArgs         = cobra.MinimumNArgs(1)
	packagesCmd          = &cobra.Command{
		Use:   "packages [SOURCE]",
		Short: "Generate a package SBOM",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from container images and filesystems",
		Example: internal.Tprintf(packagesExample, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "packages",
		}),
		Args:          packagesArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				err := cmd.Help()
				if err != nil {
					return err
				}
				// silently exit
				return fmt.Errorf("")
			}

			// set the presenter
			presenterOption := packages.ParsePresenterOption(appConfig.Output)
			if presenterOption == packages.UnknownPresenterOption {
				return fmt.Errorf("bad --output value '%s'", appConfig.Output)
			}
			packagesPresenterOpt = presenterOption

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
	///////// Formatting & Input options //////////////////////////////////////////////

	flags.StringP(
		"scope", "s", source.SquashedScope.String(),
		fmt.Sprintf("selection of layers to catalog, options=%v", source.AllScopes))

	flags.StringP(
		"output", "o", string(packages.TablePresenterOption),
		fmt.Sprintf("report output formatter, options=%v", packages.AllPresenters),
	)

	///////// Upload options //////////////////////////////////////////////////////////
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

	flags.Bool(
		"overwrite-existing-image", false,
		"overwrite an existing image during the upload to Anchore Enterprise",
	)
}

func bindPackagesConfigOptions(flags *pflag.FlagSet) error {
	///////// Formatting & Input options //////////////////////////////////////////////

	if err := viper.BindPFlag("package.cataloger.scope", flags.Lookup("scope")); err != nil {
		return err
	}

	if err := viper.BindPFlag("output", flags.Lookup("output")); err != nil {
		return err
	}

	///////// Upload options //////////////////////////////////////////////////////////

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

	return nil
}

func packagesExec(_ *cobra.Command, args []string) error {
	errs := packagesExecWorker(args[0])
	ux := ui.Select(appConfig.CliOptions.Verbosity > 0, appConfig.Quiet)
	return ux(errs, eventSubscription)
}

func packagesExecWorker(userInput string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		checkForApplicationUpdate()

		src, cleanup, err := source.New(userInput, appConfig.Registry.ToOptions())
		if err != nil {
			errs <- fmt.Errorf("failed to determine image source: %+v", err)
			return
		}
		defer cleanup()

		catalog, d, err := syft.CatalogPackages(src, appConfig.Package.Cataloger.ScopeOpt)
		if err != nil {
			errs <- fmt.Errorf("failed to catalog input: %+v", err)
			return
		}

		if appConfig.Anchore.Host != "" {
			if err := runPackageSbomUpload(src, src.Metadata, catalog, d, appConfig.Package.Cataloger.ScopeOpt); err != nil {
				errs <- err
				return
			}
		}

		bus.Publish(partybus.Event{
			Type: event.PresenterReady,
			Value: packages.Presenter(packagesPresenterOpt, packages.PresenterConfig{
				SourceMetadata: src.Metadata,
				Catalog:        catalog,
				Distro:         d,
				Scope:          appConfig.Package.Cataloger.ScopeOpt,
			}),
		})
	}()
	return errs
}

func runPackageSbomUpload(src source.Source, s source.Metadata, catalog *pkg.Catalog, d *distro.Distro, scope source.Scope) error {
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
		return fmt.Errorf("failed to create anchore client: %+v", err)
	}

	importCfg := anchore.ImportConfig{
		ImageMetadata:           src.Image.Metadata,
		SourceMetadata:          s,
		Catalog:                 catalog,
		Distro:                  d,
		Dockerfile:              dockerfileContents,
		OverwriteExistingUpload: appConfig.Anchore.OverwriteExistingImage,
		Scope:                   scope,
	}

	if err := c.Import(context.Background(), importCfg); err != nil {
		return fmt.Errorf("failed to upload results to host=%s: %+v", appConfig.Anchore.Host, err)
	}
	return nil
}

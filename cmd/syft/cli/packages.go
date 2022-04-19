package cli

import (
	"log"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/cmd/syft/cli/packages"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/logger"
	"github.com/anchore/syft/syft"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

func Packages(v *viper.Viper, app *config.Application, ro *options.RootOptions) *cobra.Command {
	o := &options.PackagesOptions{}
	cmd := &cobra.Command{
		Use:   "packages [SOURCE]",
		Short: "Generate a package SBOM",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from container images and filesystems",
		Example: internal.Tprintf(packagesHelp, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "packages",
		}),
		Args:          helpArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// this MUST be called first to make sure app config decodes
			// the viper object correctly
			if err := app.LoadAllValues(v, ro.Config); err != nil {
				return err
			}

			if app.CheckForAppUpdate {
				checkForApplicationUpdate()
			}

			// configure logging for command
			newLogWrapper(app)

			return packages.Cmd(cmd.Context(), app, args)
		},
	}

	err := o.AddFlags(cmd, v)
	if err != nil {
		log.Fatal(err)
	}

	return cmd
}

func newLogWrapper(app *config.Application) {
	cfg := logger.LogrusConfig{
		EnableConsole: (app.Log.FileLocation == "" || app.Verbosity > 0) && !app.Quiet,
		EnableFile:    app.Log.FileLocation != "",
		Level:         app.Log.LevelOpt,
		Structured:    app.Log.Structured,
		FileLocation:  app.Log.FileLocation,
	}

	logWrapper := logger.NewLogrusLogger(cfg)
	syft.SetLogger(logWrapper)
	stereoscope.SetLogger(&logger.LogrusNestedLogger{
		Logger: logWrapper.Logger.WithField("from-lib", "stereoscope"),
	})
}

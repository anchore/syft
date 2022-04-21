package cli

import (
	"log"

	"github.com/anchore/syft/cmd/syft/cli/attest"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	attestExample = `  {{.appName}} {{.command}} --output [FORMAT] --key [KEY] alpine:latest
  Supports the following image sources:
    {{.appName}} {{.command}} --key [KEY] yourrepo/yourimage:tag     defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry.
    {{.appName}} {{.command}} --key [KEY] path/to/a/file/or/dir      only for OCI tar or OCI directory
`
	attestSchemeHelp = "\n" + indent + schemeHelpHeader + "\n" + imageSchemeHelp

	attestHelp = attestExample + attestSchemeHelp
)

func Attest(v *viper.Viper, app *config.Application, ro *options.RootOptions) *cobra.Command {
	ao := options.AttestOptions{}
	cmd := &cobra.Command{
		Use:   "attest --output [FORMAT] --key [KEY] [SOURCE]",
		Short: "Generate a package SBOM as an attestation for the given [SOURCE] container image",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from a container image as the predicate of an in-toto attestation",
		Example: internal.Tprintf(attestHelp, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "attest",
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
			// configure logging for command
			newLogWrapper(app)
			logApplicationConfig(app)

			if app.CheckForAppUpdate {
				checkForApplicationUpdate()
			}

			return attest.Run(cmd.Context(), app, args)
		},
	}

	err := ao.AddFlags(cmd, v)
	if err != nil {
		log.Fatal(err)
	}

	return cmd
}

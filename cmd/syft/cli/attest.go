package cli

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/anchore/syft/cmd/syft/cli/attest"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/config"
)

const (
	attestExample = `  {{.appName}} {{.command}} --output [FORMAT] <IMAGE>
  Attest supports the following image sources:
    {{.appName}} {{.command}} yourrepo/yourimage:tag     defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry.
    {{.appName}} {{.command}} yourrepo/yourimage:tag     users of this command must have write access to the image repository for the attestation upload
`
	attestSchemeHelp = "\n" + indent + schemeHelpHeader + "\n" + imageSchemeHelp

	attestHelp = attestExample + attestSchemeHelp
)

//nolint:dupl
func Attest(v *viper.Viper, app *config.Application, ro *options.RootOptions, po *options.PackagesOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest --output [FORMAT] <IMAGE>",
		Short: "Generate an SBOM as an attestation for the given [SOURCE] container image",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from a container image as the predicate of an in-toto attestation that will be uploaded to the image registry",
		Example: internal.Tprintf(attestHelp, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "attest",
		}),
		Args: func(cmd *cobra.Command, args []string) error {
			if err := app.LoadAllValues(v, ro.Config); err != nil {
				return fmt.Errorf("unable to load configuration: %w", err)
			}

			newLogWrapper(app)
			logApplicationConfig(app)
			return validateArgs(cmd, args)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if app.CheckForAppUpdate {
				checkForApplicationUpdate()
			}

			return attest.Run(cmd.Context(), app, args)
		},
	}

	// syft attest is an enhancment of the packages command, so it should have the same flags
	err := po.AddFlags(cmd, v)
	if err != nil {
		log.Fatal(err)
	}

	return cmd
}

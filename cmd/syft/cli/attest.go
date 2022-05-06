package cli

import (
	"fmt"
	"log"

	"github.com/anchore/syft/cmd/syft/cli/attest"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/config"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
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
		Args: func(cmd *cobra.Command, args []string) error {
			// run to unmarshal viper object onto app config
			// the viper object correctly
			if err := app.LoadAllValues(v, ro.Config); err != nil {
				return fmt.Errorf("invalid application config: %v", err)
			}
			// configure logging for command
			newLogWrapper(app)
			logApplicationConfig(app)
			return validateArgs(cmd, args)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// this MUST be called first to make sure app config decodes
			// the viper object correctly
			if app.CheckForAppUpdate {
				checkForApplicationUpdate()
			}

			// build cosign key options for attestation
			ko := sign.KeyOpts{
				KeyRef:                   app.Attest.KeyRef,
				FulcioURL:                app.Attest.FulcioURL,
				IDToken:                  app.Attest.FulcioIdentityToken,
				InsecureSkipFulcioVerify: app.Attest.InsecureSkipFulcioVerify,
				RekorURL:                 app.Attest.RekorURL,
				OIDCIssuer:               app.Attest.OIDCIssuer,
				OIDCClientID:             app.Attest.OIDCClientID,
				OIDCRedirectURL:          app.Attest.OIDCRedirectURL,
			}

			return attest.Run(cmd.Context(), app, ko, args)
		},
	}

	err := ao.AddFlags(cmd, v)
	if err != nil {
		log.Fatal(err)
	}

	return cmd
}

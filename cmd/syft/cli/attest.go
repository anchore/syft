package cli

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/anchore/syft/cmd/syft/cli/attest"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal/config"
)

func Attest(v *viper.Viper, app *config.Application, ro *options.RootOptions, po *options.PackagesOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Generate an SBOM and sign it with a private/keyless key",
		Long:  "Generate an SBOM and sign it with a private/keyless key",
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

package cli

import (
	"fmt"

	"github.com/anchore/syft/cmd/syft/cli/attest"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func Attest(v *viper.Viper, app *config.Application, ro *options.RootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Foo bar Baz",
		Long:  "Foo bar Baz",
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

	return cmd
}

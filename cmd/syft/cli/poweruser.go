package cli

import (
	"fmt"

	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/cmd/syft/cli/poweruser"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const powerUserExample = `  {{.appName}} {{.command}} <image>
  DEPRECATED - THIS COMMAND WILL BE REMOVED in v1.0.0
  Only image sources are supported (e.g. docker: , podman: , docker-archive: , oci: , etc.), the directory source (dir:) is not supported.
  All behavior is controlled via application configuration and environment variables (see https://github.com/anchore/syft#configuration)
`

func PowerUser(v *viper.Viper, app *config.Application, ro *options.RootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "power-user [IMAGE]",
		Short: "Run bulk operations on container images",
		Example: internal.Tprintf(powerUserExample, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "power-user",
		}),
		Args: func(cmd *cobra.Command, args []string) error {
			if err := app.LoadAllValues(v, ro.Config); err != nil {
				return fmt.Errorf("invalid application config: %v", err)
			}
			// configure logging for command
			newLogWrapper(app)
			logApplicationConfig(app)
			return validateArgs(cmd, args)
		},
		Hidden:        true,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if app.CheckForAppUpdate {
				checkForApplicationUpdate()
			}
			return poweruser.Run(cmd.Context(), app, args)
		},
	}

	return cmd
}

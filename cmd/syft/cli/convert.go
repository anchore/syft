package cli

import (
	"fmt"

	"github.com/anchore/syft/cmd/syft/cli/convert"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	convertExample = `  {{.appName}} {{.command}} alpine.syft.json -o alpine.spdx.xml
`
)

func Convert(v *viper.Viper, app *config.Application, ro *options.RootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "convert original.json -o [FORMAT]",
		Short: "Convert between SBOM formats",
		Long:  "",
		Example: internal.Tprintf(convertExample, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "convert",
		}),
		Args: func(cmd *cobra.Command, args []string) error {
			if err := app.LoadAllValues(v, ro.Config); err != nil {
				return fmt.Errorf("invalida application config: %w", err)
			}
			newLogWrapper(app)
			logApplicationConfig(app)
			return validateArgs(cmd, args)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// newLogWrapper(app)
			// logApplicationConfig(app)
			if app.CheckForAppUpdate {
				checkForApplicationUpdate()
			}
			return convert.Run(cmd.Context(), app, args)
		},
	}
	return cmd
}

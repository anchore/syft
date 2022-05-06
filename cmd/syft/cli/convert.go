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
	convertExample = `  {{.appName}} {{.command}} img.syft.json -o spdx-json                      convert a syft SBOM to spdx-json, output goes to stdout in table format, by default
  {{.appName}} {{.command}} img.syft.json -o cyclonedx-json=img.cdx.json    convert a syft SBOM to CycloneDX, output goes to a file named img.cdx.json
`
)

func Convert(v *viper.Viper, app *config.Application, ro *options.RootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "convert [SOURCE-SBOM] -o [FORMAT]",
		Short: "Convert between SBOM formats",
		Long:  "[Experimental] Convert SBOM files to, and from, SPDX, CycloneDX and Syft's format. For more info about data loss between formats see https://github.com/anchore/syft#format-conversion-experimental",
		Example: internal.Tprintf(convertExample, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "convert",
		}),
		Args: func(cmd *cobra.Command, args []string) error {
			if err := app.LoadAllValues(v, ro.Config); err != nil {
				return fmt.Errorf("invalid application config: %w", err)
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
			return convert.Run(cmd.Context(), app, args)
		},
	}
	return cmd
}

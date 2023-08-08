package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
)

const (
	convertExample = `  {{.appName}} {{.command}} img.syft.json -o spdx-json                      convert a syft SBOM to spdx-json, output goes to stdout
  {{.appName}} {{.command}} img.syft.json -o cyclonedx-json=img.cdx.json    convert a syft SBOM to CycloneDX, output is written to the file "img.cdx.json""
  {{.appName}} {{.command}} - -o spdx-json                                  convert an SBOM from STDIN to spdx-json
`
)

type ConvertOptions struct {
	options.Output      `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
}

//nolint:dupl
func Convert(app clio.Application) *cobra.Command {
	opts := &ConvertOptions{
		UpdateCheck: options.UpdateCheckDefault(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "convert [SOURCE-SBOM] -o [FORMAT]",
		Short: "Convert between SBOM formats",
		Long:  "[Experimental] Convert SBOM files to, and from, SPDX, CycloneDX and Syft's format. For more info about data loss between formats see https://github.com/anchore/syft#format-conversion-experimental",
		Example: internal.Tprintf(convertExample, map[string]interface{}{
			"appName": app.ID().Name,
			"command": "convert",
		}),
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}

			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.CheckForAppUpdate {
				checkForApplicationUpdate(app)
			}
			return RunConvert(opts, args[0])
		},
	}, opts)
}

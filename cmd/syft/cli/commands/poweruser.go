package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
)

const powerUserExample = `  {{.appName}} {{.command}} <image>
  DEPRECATED - THIS COMMAND WILL BE REMOVED in v1.0.0
  Only image sources are supported (e.g. docker: , podman: , docker-archive: , oci: , etc.), the directory source (dir:) is not supported, template outputs are not supported.
  All behavior is controlled via application configuration and environment variables (see https://github.com/anchore/syft#configuration)
`

type powerUserOptions struct {
	options.OutputFile  `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	options.Packages    `yaml:",inline" mapstructure:",squash"`
}

func PowerUser(app clio.Application) *cobra.Command {
	pkgs := options.PackagesDefault()
	pkgs.Secrets.Cataloger.Enabled = true
	pkgs.FileMetadata.Cataloger.Enabled = true
	pkgs.FileContents.Cataloger.Enabled = true
	pkgs.FileClassification.Cataloger.Enabled = true
	opts := &powerUserOptions{
		Packages: pkgs,
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "power-user [IMAGE]",
		Short: "Run bulk operations on container images",
		Example: internal.Tprintf(powerUserExample, map[string]interface{}{
			"appName": app.ID().Name,
			"command": "power-user",
		}),
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}

			return validateArgs(cmd, args)
		},
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.CheckForAppUpdate {
				checkForApplicationUpdate(app)
			}
			return runPowerUser(app, opts, args[0])
		},
	}, opts)
}

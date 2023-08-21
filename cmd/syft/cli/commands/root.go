package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/bus"
)

func Root(app clio.Application, packagesCmd *cobra.Command) *cobra.Command {
	opts := packagesOptionsDefault()

	return app.SetupRootCommand(&cobra.Command{
		Use:     fmt.Sprintf("%s [SOURCE]", app.ID().Name),
		Short:   packagesCmd.Short,
		Long:    packagesCmd.Long,
		Args:    packagesCmd.Args,
		Example: packagesCmd.Example,
		RunE: func(cmd *cobra.Command, args []string) error {
			defer bus.Exit()

			applicationUpdateCheck(app, opts.CheckForAppUpdate)

			return runPackages(app, opts, args[0])
		},
	}, opts)
}

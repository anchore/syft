package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

func Root(app clio.Application, packagesCmd *cobra.Command) *cobra.Command {
	opts := packagesOptionsDefault()

	return app.SetupRootCommand(&cobra.Command{
		Use:     fmt.Sprintf("%s [SOURCE]", app.ID().Name),
		Short:   packagesCmd.Short,
		Long:    packagesCmd.Long,
		Args:    packagesCmd.Args,
		Example: packagesCmd.Example,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.CheckForAppUpdate {
				checkForApplicationUpdate(app)
			}
			return runPackages(app, opts, args[0])
		},
	}, opts)
}

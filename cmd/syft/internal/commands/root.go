package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal/ui"
)

func Root(app clio.Application, packagesCmd *cobra.Command) *cobra.Command {
	id := app.ID()

	opts := defaultScanOptions()

	return app.SetupRootCommand(&cobra.Command{
		Use:     fmt.Sprintf("%s [SOURCE]", app.ID().Name),
		Short:   packagesCmd.Short,
		Long:    packagesCmd.Long,
		Args:    packagesCmd.Args,
		Example: packagesCmd.Example,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(cmd *cobra.Command, args []string) error {
			restoreStdout := ui.CaptureStdoutToTraceLog()
			defer restoreStdout()

			return runScan(cmd.Context(), id, opts, args[0])
		},
	}, opts)
}

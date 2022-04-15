package cli

import (
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/spf13/cobra"
)

var (
	ro = &options.RootOptions{}
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:               internal.ApplicationName,
		DisableAutoGenTag: true,
		SilenceUsage:      true,
	}

	ro.AddFlags(cmd)
	cmd.AddCommand(Packages())
	return cmd
}

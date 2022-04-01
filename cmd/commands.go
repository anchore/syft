package cmd

import (
	"github.com/anchore/syft/cmd/options"
	"github.com/anchore/syft/internal/version"
	"github.com/spf13/cobra"
)

var (
	ro = &options.RootOptions{}
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Short:             Packages().Short,
		Long:              Packages().Long,
		Args:              Packages().Args,
		Example:           Packages().Example,
		SilenceUsage:      true,
		SilenceErrors:     true,
		PreRunE:           Packages().PreRunE,
		RunE:              Packages().RunE,
		ValidArgsFunction: Packages().ValidArgsFunction,
		Version:           version.FromBuild().Version,
	}
	ro.AddFlags(cmd)

	// TODO: Add syft sub-commands
	cmd.AddCommand(Packages())
	cmd.AddCommand(Version())
	return cmd
}

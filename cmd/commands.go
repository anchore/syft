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
		Short:             packagesCmd.Short,
		Long:              packagesCmd.Long,
		Args:              packagesCmd.Args,
		Example:           packagesCmd.Example,
		SilenceUsage:      true,
		SilenceErrors:     true,
		PreRunE:           packagesCmd.PreRunE,
		RunE:              packagesCmd.RunE,
		ValidArgsFunction: packagesCmd.ValidArgsFunction,
		Version:           version.FromBuild().Version,
	}
	ro.AddFlags(cmd)

	// TODO: Add syft sub-commands

	return cmd
}

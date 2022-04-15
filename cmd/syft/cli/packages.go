package cli

import (
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/cmd/syft/cli/packages"
	"github.com/spf13/cobra"
)

func Packages() *cobra.Command {
	o := &options.PackagesOptions{}

	cmd := &cobra.Command{
		Use:           "packages [SOURCE]",
		Short:         "Generate a package SBOM",
		Long:          "Generate a packaged-based Software Bill Of Materials (SBOM) from container images and filesystems",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return packages.PackagesCmd(cmd.Context(), o, args)
		},
	}

	o.AddFlags(cmd)
	return cmd
}

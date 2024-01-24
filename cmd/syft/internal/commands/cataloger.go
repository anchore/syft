package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

func Cataloger(app clio.Application) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cataloger",
		Short: "Show available catalogers and configuration",
	}

	cmd.AddCommand(
		CatalogerList(app),
	)

	return cmd
}

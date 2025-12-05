package commands

import (
	"os"

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

	// only add cataloger info command if experimental capabilities feature is enabled
	if isCapabilitiesExperimentEnabled() {
		cmd.AddCommand(CatalogerCaps(app))
	}

	return cmd
}

func isCapabilitiesExperimentEnabled() bool {
	return os.Getenv("SYFT_EXP_CAPABILITIES") == "true"
}

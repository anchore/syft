package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"

	"github.com/spf13/cobra"
)

var cpeImportCmd = &cobra.Command{
	Use:   "import",
	Short: "import a CPE dictionary archive",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ret := runCPEImportCmd(cmd, args)
		if ret != 0 {
			fmt.Println("Unable to import CPE dictionary archive")
		}
		os.Exit(ret)
	},
}

func init() {
	cpeCmd.AddCommand(cpeImportCmd)
}

func runCPEImportCmd(_ *cobra.Command, args []string) int {
	cpeCurator := cpe.NewCurator(appConfig.CPEDictionary)

	if err := cpeCurator.ImportFrom(args[0]); err != nil {
		log.Errorf("unable to import CPE dictionary: %+v", err)
		return 1
	}

	fmt.Println("CPE dictionary imported")
	return 0
}

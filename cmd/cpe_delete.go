package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"

	"github.com/spf13/cobra"
)

var cpeDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete the vulnerability database",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ret := runCPEDeleteCmd(cmd, args)
		if ret != 0 {
			fmt.Println("Unable to delete vulnerability database")
		}
		os.Exit(ret)
	},
}

func init() {
	cpeCmd.AddCommand(cpeDeleteCmd)
}

func runCPEDeleteCmd(_ *cobra.Command, _ []string) int {
	cpeCurator := cpe.NewCurator(appConfig.CPEDictionary)

	if err := cpeCurator.Delete(); err != nil {
		log.Errorf("unable to delete CPE dictionary: %+v", err)
		return 1
	}

	fmt.Println("CPE dictionary deleted")
	return 0
}

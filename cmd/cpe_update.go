package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"

	"github.com/spf13/cobra"
)

var cpeUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "download the latest CPE dictionary",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ret := runCPEUpdateCmd(cmd, args)
		if ret != 0 {
			fmt.Println("Unable to update CPE dictionary")
		}
		os.Exit(ret)
	},
}

func init() {
	cpeCmd.AddCommand(cpeUpdateCmd)
}

func runCPEUpdateCmd(_ *cobra.Command, _ []string) int {
	cpeCurator := cpe.NewCurator(appConfig.CPEDictionary)

	updated, err := cpeCurator.Update()
	if err != nil {
		log.Errorf("unable to update CPE dictionary: %+v", err)
		return 1
	}

	if updated {
		fmt.Println("CPE dictionary updated!")
		return 0
	}

	fmt.Println("No CPE dictionary update available")
	return 0
}

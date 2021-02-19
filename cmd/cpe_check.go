package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"

	"github.com/spf13/cobra"
)

var cpeCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "check to see if there is a CPE dictionary update available",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ret := runCPECheckCmd(cmd, args)
		if ret != 0 {
			fmt.Println("Unable to check for CPE dictionary updates")
		}
		os.Exit(ret)
	},
}

func init() {
	cpeCmd.AddCommand(cpeCheckCmd)
}

func runCPECheckCmd(_ *cobra.Command, _ []string) int {
	cpeCurator := cpe.NewCurator(appConfig.CPEDictionary)

	updateAvailable, _, err := cpeCurator.IsUpdateAvailable()
	if err != nil {
		log.Errorf("unable to check for vulnerability database update: %+v", err)
		return 1
	}

	if !updateAvailable {
		fmt.Println("No update available")
		return 0
	}

	fmt.Println("Update available!")
	return 0
}

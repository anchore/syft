package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "display CPE dictionary status",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		err := runCPEStatusCmd(cmd, args)
		if err != nil {
			log.Errorf(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	cpeCmd.AddCommand(statusCmd)
}

func runCPEStatusCmd(_ *cobra.Command, _ []string) error {
	cpeCurator := cpe.NewCurator(appConfig.CPEDictionary)
	status := cpeCurator.Status()

	if status.Err != nil {
		return status.Err
	}

	fmt.Println("Location: ", status.Location)
	fmt.Println("Date: ", status.Date.String())
	fmt.Println("Entries: ", status.Entries)
	fmt.Println("Status: Valid")
	return nil
}

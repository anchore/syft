package cmd

import (
	"github.com/spf13/cobra"
)

var cpeCmd = &cobra.Command{
	Use:   "cpe",
	Short: "CPE dictionary operations",
}

func init() {
	rootCmd.AddCommand(cpeCmd)
}

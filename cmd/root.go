package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

const ApplicationName = "imgbom"

var rootOptions struct {
	cfgFile   string
}

var rootCmd = &cobra.Command{
	Use:   ApplicationName,
	Short: "A container image BOM tool",
	Long:  `todo.`,
	Run:    doRunCmd,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(loadApplicationConfig)
	rootCmd.PersistentFlags().StringVar(&rootOptions.cfgFile, "config", "", "config file")
}

func loadApplicationConfig() {
	// TODO...
}

func doRunCmd(cmd *cobra.Command, args []string) {

}
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/anchore/syft/internal"

	"github.com/anchore/syft/internal/version"
	"github.com/spf13/cobra"
)

var versionCmdOutputFormat string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "show the version",
	Run:   printVersion,
}

func init() {
	versionCmd.Flags().StringVarP(&versionCmdOutputFormat, "output", "o", "text", "format to show version information (available=[text, json])")
	rootCmd.AddCommand(versionCmd)
}

func printVersion(_ *cobra.Command, _ []string) {
	versionInfo := version.FromBuild()

	switch versionCmdOutputFormat {
	case "text":
		fmt.Println("Application:       ", internal.ApplicationName)
		fmt.Println("Version:           ", versionInfo.Version)
		fmt.Println("JsonSchemaVersion: ", internal.JSONSchemaVersion)
		fmt.Println("BuildDate:         ", versionInfo.BuildDate)
		fmt.Println("GitCommit:         ", versionInfo.GitCommit)
		fmt.Println("GitDescription:    ", versionInfo.GitDescription)
		fmt.Println("Platform:          ", versionInfo.Platform)
		fmt.Println("GoVersion:         ", versionInfo.GoVersion)
		fmt.Println("Compiler:          ", versionInfo.Compiler)

	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		err := enc.Encode(&struct {
			version.Version
			Application string `json:"application"`
		}{
			Version:     versionInfo,
			Application: internal.ApplicationName,
		})
		if err != nil {
			fmt.Printf("failed to show version information: %+v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("unsupported output format: %s\n", versionCmdOutputFormat)
		os.Exit(1)
	}
}

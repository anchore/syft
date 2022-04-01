package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/anchore/syft/cmd/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/spf13/cobra"
	"os"
)

func Version() *cobra.Command {
	o := &options.VersionOptions{}
	cmd := &cobra.Command{
		Use:   "version",
		Short: "show the version",
		RunE: func(cmd *cobra.Command, args []string) error {
			printVersion(o.Output)
			return nil
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func printVersion(output string) {
	versionInfo := version.FromBuild()

	switch output {
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
		fmt.Printf("unsupported output format: %s\n", output)
		os.Exit(1)
	}
}

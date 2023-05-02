package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	fangs "github.com/anchore/fangs/config"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/version"
)

type VersionOptions struct {
	Output string `mapstructure:"output"`
}

func Version(app *config.Application) *cobra.Command {
	o := &VersionOptions{
		Output: "text",
	}
	cmd := &cobra.Command{
		Use:   "version",
		Short: "show the version",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := fangs.Load(app.FangsConfig(), cmd, o)
			if err != nil {
				return err
			}
			return printVersion(o.Output)
		},
	}

	AddVersionFlags(cmd.Flags(), o)

	return cmd
}

func AddVersionFlags(flags *pflag.FlagSet, o *VersionOptions) {
	flags.StringVarP(&o.Output, "output", "o", o.Output, "format to show version information (available=[text, json])")
}

func printVersion(output string) error {
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

	return nil
}

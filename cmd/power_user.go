package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/gookit/color"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"
)

const powerUserExample = `  {{.appName}} {{.command}} <image>

  DEPRECATED - THIS COMMAND WILL BE REMOVED in v1.0.0

  Only image sources are supported (e.g. docker: , docker-archive: , oci: , etc.), the directory source (dir:) is not supported.

  All behavior is controlled via application configuration and environment variables (see https://github.com/anchore/syft#configuration)
`

var powerUserOpts = struct {
	configPath string
}{}

var powerUserCmd = &cobra.Command{
	Use:   "power-user [IMAGE]",
	Short: "Run bulk operations on container images",
	Example: internal.Tprintf(powerUserExample, map[string]interface{}{
		"appName": internal.ApplicationName,
		"command": "power-user",
	}),
	Args:          validateInputArgs,
	Hidden:        true,
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if appConfig.Dev.ProfileCPU && appConfig.Dev.ProfileMem {
			return fmt.Errorf("cannot profile CPU and memory simultaneously")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if appConfig.Dev.ProfileCPU {
			defer profile.Start(profile.CPUProfile).Stop()
		} else if appConfig.Dev.ProfileMem {
			defer profile.Start(profile.MemProfile).Stop()
		}

		return powerUserExec(cmd, args)
	},
	ValidArgsFunction: dockerImageValidArgsFunction,
}

func init() {
	powerUserCmd.Flags().StringVarP(&powerUserOpts.configPath, "config", "c", "", "config file path with all power-user options")

	rootCmd.AddCommand(powerUserCmd)
}

func powerUserExec(_ *cobra.Command, args []string) error {
	// could be an image or a directory, with or without a scheme
	userInput := args[0]

	writer, err := makeWriter()
	if err != nil {
		return err
	}

	defer func() {
		if err := writer.Close(); err != nil {
			log.Warnf("unable to write to report destination: %w", err)
		}

		// inform user at end of run that command will be removed
		deprecated := color.Style{color.Red, color.OpBold}.Sprint("DEPRECATED: This command will be removed in v1.0.0")
		_, _ = fmt.Fprintln(os.Stderr, deprecated)
	}()

	return eventLoop(
		powerUserExecWorker(userInput, writer),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet)...,
	)
}
func powerUserExecWorker(userInput string, writer sbom.Writer) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		appConfig.Secrets.Cataloger.Enabled = true
		appConfig.FileMetadata.Cataloger.Enabled = true
		appConfig.FileContents.Cataloger.Enabled = true
		appConfig.FileClassification.Cataloger.Enabled = true
		tasks, err := tasks()
		if err != nil {
			errs <- err
			return
		}

		src, cleanup, err := source.New(userInput, appConfig.Registry.ToOptions(), appConfig.Exclusions)
		if err != nil {
			errs <- err
			return
		}
		if cleanup != nil {
			defer cleanup()
		}

		s := sbom.SBOM{
			Source: src.Metadata,
			Descriptor: sbom.Descriptor{
				Name:          internal.ApplicationName,
				Version:       version.FromBuild().Version,
				Configuration: appConfig,
			},
		}

		var relationships []<-chan artifact.Relationship
		for _, task := range tasks {
			c := make(chan artifact.Relationship)
			relationships = append(relationships, c)

			go runTask(task, &s.Artifacts, src, c, errs)
		}

		s.Relationships = append(s.Relationships, mergeRelationships(relationships...)...)

		bus.Publish(partybus.Event{
			Type:  event.SBOMReady,
			Value: func() error { return writer.Write(s) },
		})
	}()

	return errs
}

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/sbom"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"
)

const (
	convertExample = `  {{.appName}} {{.command}} original.json --to [FORMAT]
`
)

func init() {
	setPackageFlags(convertCmd.Flags())
	rootCmd.AddCommand(convertCmd)
}

var (
	convertCmd = &cobra.Command{
		Use:           "convert original.json -o [FORMAT]",
		Args:          validateInputArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if appConfig.Dev.ProfileCPU {
				defer profile.Start(profile.CPUProfile).Stop()
			} else if appConfig.Dev.ProfileMem {
				defer profile.Start(profile.MemProfile).Stop()
			}

			return convertExec(cmd.Context(), cmd, args)
		},
	}
)

func convertExec(ctx context.Context, _ *cobra.Command, args []string) error {
	writer, err := makeWriter(appConfig.Outputs, appConfig.File)
	if err != nil {
		return err
	}

	defer func() {
		if err := writer.Close(); err != nil {
			log.Warnf("unable to write to report destination: %w", err)
		}
	}()

	// this can only be a SBOM file
	userInput := args[0]
	f, err := os.Open(userInput)
	if err != nil {
		return fmt.Errorf("failed to open SBOM file: %w", err)
	}
	defer f.Close()

	sbom, format, err := syft.Decode(f)
	if err != nil {
		return fmt.Errorf("failed to decode SBOM: %w", err)
	}
	log.Infof("loaded sbom with %s format", format)

	// TODO: handle unsupported formats, like github's

	return eventLoop(
		convertExecWorker(sbom, writer),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet)...,
	)
}

func convertExecWorker(s *sbom.SBOM, w sbom.Writer) <-chan error {
	errs := make(chan error)

	go func() {
		bus.Publish(partybus.Event{
			Type:  event.Exit,
			Value: func() error { return w.Write(*s) },
		})

	}()
	return errs
}

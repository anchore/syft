package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/formats/cyclonedxjson"
	"github.com/anchore/syft/internal/formats/cyclonedxxml"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/spdx22tagvalue"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/sbom"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wagoodman/go-partybus"
)

const (
	convertExample = `  {{.appName}} {{.command}} alpine.syft.json -o alpine.spdx.xml
`
)

var convertableFormats = []sbom.FormatID{
	syftjson.ID,
	spdx22json.ID,
	spdx22tagvalue.ID,
	cyclonedxjson.ID,
	cyclonedxxml.ID,
}

func init() {
	setConvertFlags(convertCmd.Flags())
	rootCmd.AddCommand(convertCmd)
}

var (
	convertCmd = &cobra.Command{
		Use:   "convert original.json -o [FORMAT]",
		Short: "Convert between SBOM formats",
		Long:  "",
		Example: internal.Tprintf(convertExample, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "convert",
		}),
		Args:          validateInputArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if appConfig.Dev.ProfileCPU {
				defer profile.Start(profile.CPUProfile).Stop()
			} else if appConfig.Dev.ProfileMem {
				defer profile.Start(profile.MemProfile).Stop()
			}

			return convertExec(cmd, args)
		},
	}
)

func setConvertFlags(flags *pflag.FlagSet) {
	flags.StringP(
		"output", "o", string(table.ID),
		fmt.Sprintf("report output format, options=%v", formatAliases(syft.FormatIDs()...)),
	)
}

func convertExec(_ *cobra.Command, args []string) error {
	log.Debugf("output options: %+v", appConfig.Outputs)

	outputFormat := syft.FormatByName(appConfig.Outputs[0])
	if !isSupportedFormat(outputFormat.ID()) {
		return fmt.Errorf("cannot convert to %s", outputFormat.ID())
	}

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

	sbom, inputFormat, err := syft.Decode(f)
	if err != nil {
		return fmt.Errorf("failed to decode SBOM: %w", err)
	}

	if !isSupportedFormat(inputFormat.ID()) {
		return fmt.Errorf("cannot convert from %s format", outputFormat.ID())
	}

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
		defer close(errs)
		bus.Publish(partybus.Event{
			Type:  event.Exit,
			Value: func() error { return w.Write(*s) },
		})
	}()
	return errs
}

func isSupportedFormat(format sbom.FormatID) bool {
	for _, f := range convertableFormats {
		if format == f {
			return true
		}
	}

	return false
}

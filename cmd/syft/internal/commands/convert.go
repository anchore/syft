package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format"
)

const (
	convertExample = `  {{.appName}} {{.command}} img.syft.json -o spdx-json                      convert a syft SBOM to spdx-json, output goes to stdout
  {{.appName}} {{.command}} img.syft.json -o cyclonedx-json=img.cdx.json    convert a syft SBOM to CycloneDX, output is written to the file "img.cdx.json"
  {{.appName}} {{.command}} - -o spdx-json                                  convert an SBOM from STDIN to spdx-json
`
)

type ConvertOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.Output      `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
}

func Convert(app clio.Application) *cobra.Command {
	id := app.ID()

	opts := &ConvertOptions{
		UpdateCheck: options.DefaultUpdateCheck(),
		Output:      options.DefaultOutput(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "convert [SOURCE-SBOM] -o [FORMAT]",
		Short: "Convert between SBOM formats",
		Long:  "[Experimental] Convert SBOM files to, and from, SPDX, CycloneDX and Syft's format. For more info about data loss between formats see https://github.com/anchore/syft/wiki/format-conversion",
		Example: internal.Tprintf(convertExample, map[string]interface{}{
			"appName": id.Name,
			"command": "convert",
		}),
		Args:    validateConvertArgs,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(_ *cobra.Command, args []string) error {
			restoreStdout := ui.CaptureStdoutToTraceLog()
			defer restoreStdout()

			return RunConvert(opts, args[0])
		},
	}, opts)
}

func validateConvertArgs(cmd *cobra.Command, args []string) error {
	return validateArgs(cmd, args, "an SBOM argument is required")
}

func RunConvert(opts *ConvertOptions, userInput string) error {
	log.Warn("convert is an experimental feature, run `syft convert -h` for help")

	writer, err := opts.SBOMWriter()
	if err != nil {
		return err
	}

	var reader io.ReadSeekCloser

	if userInput == "-" {
		// though os.Stdin is an os.File, it does not support seeking
		// you will get errors such as "seek /dev/stdin: illegal seek".
		// We need to buffer what we read.
		reader = internal.NewBufferedSeeker(os.Stdin)
	} else {
		f, err := os.Open(userInput)
		if err != nil {
			return fmt.Errorf("failed to open SBOM file: %w", err)
		}
		defer func() {
			_ = f.Close()
		}()
		reader = f
	}

	s, _, _, err := format.Decode(reader)
	if err != nil {
		return fmt.Errorf("failed to decode SBOM: %w", err)
	}

	if s == nil {
		return fmt.Errorf("no SBOM produced")
	}

	if err := writer.Write(*s); err != nil {
		return fmt.Errorf("failed to write SBOM: %w", err)
	}

	return nil
}

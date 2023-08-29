package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/formats"
)

const (
	convertExample = `  {{.appName}} {{.command}} img.syft.json -o spdx-json                      convert a syft SBOM to spdx-json, output goes to stdout
  {{.appName}} {{.command}} img.syft.json -o cyclonedx-json=img.cdx.json    convert a syft SBOM to CycloneDX, output is written to the file "img.cdx.json""
  {{.appName}} {{.command}} - -o spdx-json                                  convert an SBOM from STDIN to spdx-json
`
)

type ConvertOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.MultiOutput `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
}

//nolint:dupl
func Convert(app clio.Application) *cobra.Command {
	id := app.ID()

	opts := &ConvertOptions{
		UpdateCheck: options.DefaultUpdateCheck(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "convert [SOURCE-SBOM] -o [FORMAT]",
		Short: "Convert between SBOM formats",
		Long:  "[Experimental] Convert SBOM files to, and from, SPDX, CycloneDX and Syft's format. For more info about data loss between formats see https://github.com/anchore/syft#format-conversion-experimental",
		Example: internal.Tprintf(convertExample, map[string]interface{}{
			"appName": id.Name,
			"command": "convert",
		}),
		Args:    validateConvertArgs,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(cmd *cobra.Command, args []string) error {
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

	var reader io.ReadCloser

	if userInput == "-" {
		reader = os.Stdin
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

	s, _, err := formats.Decode(reader)
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

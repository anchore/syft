package commands

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/go-homedir"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

const (
	convertExample = `  {{.appName}} {{.command}} img.syft.json -o spdx-json                      convert a syft SBOM to spdx-json, output goes to stdout
  {{.appName}} {{.command}} img.syft.json -o cyclonedx-json=img.cdx.json    convert a syft SBOM to CycloneDX, output is written to the file "img.cdx.json"
  {{.appName}} {{.command}} - -o spdx-json                                  convert an SBOM from STDIN to spdx-json
  SYFT_CONVERT_PASSTHROUGH_EXACT_FORMAT=true {{.appName}} {{.command}} img.syft.json -o syft-json=out.syft.json    copy the input to "out.syft.json" unchanged if it is already syft-json at the current schema version
`
)

type ConvertOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.Output      `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	Convert             options.Convert `yaml:"convert" json:"convert" mapstructure:"convert"`
}

func Convert(app clio.Application) *cobra.Command {
	id := app.ID()

	opts := &ConvertOptions{
		UpdateCheck: options.DefaultUpdateCheck(),
		Output:      options.DefaultOutput(),
		Convert:     options.DefaultConvert(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "convert [SOURCE-SBOM] -o [FORMAT]",
		Short: "Convert between SBOM formats",
		Long:  "[Experimental] Convert SBOM files to, and from, SPDX, CycloneDX and Syft's format. For more info about data loss between formats see https://github.com/anchore/syft/wiki/format-conversion",
		Example: internal.Tprintf(convertExample, map[string]any{
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

	content, err := readConvertInput(userInput)
	if err != nil {
		return err
	}

	outputs := opts.Outputs
	var unchanged []string
	if opts.Convert.PassthroughExactFormat {
		log.Warn("convert.passthrough-exact-format is enabled: syft-json input that already exactly matches a requested output format and schema version will be copied to that output unchanged (this does not apply to any other input format)")

		unchanged, outputs, err = partitionOutputsBySourceFormat(opts.Output, content)
		if err != nil {
			return err
		}
	}

	// resolve (and validate) every output that needs converting before writing anything, so that
	// a bad -o value fails the command without leaving partial results behind
	var writer sbom.Writer
	if len(outputs) > 0 {
		outputOpts := opts.Output
		outputOpts.Outputs = outputs
		writer, err = outputOpts.SBOMWriter()
		if err != nil {
			return err
		}
	}

	for _, output := range unchanged {
		if err := writeUnchanged(output, opts.LegacyFile, content); err != nil {
			return err
		}
	}

	if writer == nil {
		return nil
	}

	s, _, _, err := format.Decode(bytes.NewReader(content))
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

// readConvertInput reads the whole SBOM document from the given path (or STDIN when "-"). The document is held in
// memory so it can be identified, copied, and decoded independently without relying on the input being seekable.
func readConvertInput(userInput string) ([]byte, error) {
	if userInput == "-" {
		content, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read SBOM from STDIN: %w", err)
		}
		return content, nil
	}

	content, err := os.ReadFile(userInput)
	if err != nil {
		return nil, fmt.Errorf("failed to open SBOM file: %w", err)
	}
	return content, nil
}

// partitionOutputsBySourceFormat splits the requested outputs (in "<format>[@<version>][=<path>]" form) into those
// that exactly match the format and schema version of a syft-json input document (which can be written out
// unchanged) and those that still require conversion. Input in any other format is always converted. Outputs that
// cannot be resolved to an encoder are left for the writer to report on.
func partitionOutputsBySourceFormat(output options.Output, content []byte) (unchanged []string, toConvert []string, err error) {
	id, version := format.Identify(bytes.NewReader(content))
	if id == "" || version == "" {
		// let decoding surface the appropriate error
		return nil, output.Outputs, nil
	}

	if id != syftjson.ID {
		log.WithFields("format", id, "version", version).Debug("input is not syft-json, passthrough does not apply")
		return nil, output.Outputs, nil
	}

	encoders, err := output.Encoders()
	if err != nil {
		return nil, nil, err
	}
	collection := format.NewEncoderCollection(encoders...)

	for _, out := range output.Outputs {
		name, _, _ := strings.Cut(strings.TrimSpace(out), "=")
		enc := collection.GetByString(name)
		if enc != nil && enc.ID() == id && enc.Version() == version {
			log.WithFields("format", id, "version", version, "output", out).Warn("input already exactly matches the requested output format and schema version, copying it unchanged instead of converting it")
			unchanged = append(unchanged, out)
			continue
		}
		toConvert = append(toConvert, out)
	}

	return unchanged, toConvert, nil
}

// writeUnchanged writes the SBOM document as-is to the destination described by the given "<format>[=<path>]"
// output value, falling back to the (deprecated) --file path, and finally to the report bus (STDOUT).
func writeUnchanged(output string, defaultFile string, content []byte) error {
	_, path, _ := strings.Cut(strings.TrimSpace(output), "=")
	if path == "" {
		path = defaultFile
	}

	if path == "" {
		bus.Report(string(content))
		return nil
	}

	expandedPath, err := homedir.Expand(path)
	if err != nil {
		log.Warnf("could not expand given writer output path=%q: %w", path, err)
		expandedPath = path
	}

	if dir := filepath.Dir(expandedPath); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("unable to create report directory: %w", err)
		}
	}

	if err := os.WriteFile(expandedPath, content, 0644); err != nil {
		return fmt.Errorf("unable to create report file: %w", err)
	}

	return nil
}

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

	reader, inputPath, err := openConvertInput(userInput)
	if err != nil {
		return err
	}
	defer func() {
		_ = reader.Close()
	}()

	outputs := opts.Outputs
	var unchanged []string
	if opts.Convert.PassthroughExactFormat {
		log.Warn("convert.passthrough-exact-format is enabled: syft-json input that already exactly matches a requested output format and schema version will be copied to that output unchanged (this does not apply to any other input format)")

		unchanged, outputs, err = partitionOutputsBySourceFormat(opts.Output, reader)
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
		if err := writeUnchanged(output, opts.LegacyFile, inputPath, reader); err != nil {
			return err
		}
	}

	if writer == nil {
		return nil
	}

	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("unable to seek to start of SBOM: %w", err)
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

// openConvertInput opens the SBOM document at the given path, or STDIN when "-". The returned reader is seekable so
// the document can be identified, copied, and decoded in turn without being loaded into memory. The returned path
// is empty when reading from STDIN.
func openConvertInput(userInput string) (io.ReadSeekCloser, string, error) {
	if userInput == "-" {
		reader, err := openStdin()
		if err != nil {
			return nil, "", err
		}
		return reader, "", nil
	}

	f, err := os.Open(userInput)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open SBOM file: %w", err)
	}
	return f, userInput, nil
}

// openStdin returns a seekable view of STDIN. When STDIN is a regular file (such as a shell redirect) it is read in
// place; a pipe or terminal cannot seek (you will get errors such as "seek /dev/stdin: illegal seek"), so it is
// read fully into memory instead.
func openStdin() (io.ReadSeekCloser, error) {
	if info, err := os.Stdin.Stat(); err == nil && info.Mode().IsRegular() {
		if start, err := os.Stdin.Seek(0, io.SeekCurrent); err == nil {
			return readSeekNopCloser{io.NewSectionReader(os.Stdin, start, info.Size()-start)}, nil
		}
	}

	content, err := io.ReadAll(os.Stdin) //nolint:gocritic // a piped SBOM has no known size and must be buffered to be seekable
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM from STDIN: %w", err)
	}
	return readSeekNopCloser{bytes.NewReader(content)}, nil
}

type readSeekNopCloser struct {
	io.ReadSeeker
}

func (readSeekNopCloser) Close() error {
	return nil
}

// partitionOutputsBySourceFormat splits the requested outputs (in "<format>[@<version>][=<path>]" form) into those
// that exactly match the format and schema version of a syft-json input document (which can be written out
// unchanged) and those that still require conversion. Input in any other format is always converted. Outputs that
// cannot be resolved to an encoder are left for the writer to report on.
func partitionOutputsBySourceFormat(output options.Output, reader io.ReadSeeker) (unchanged []string, toConvert []string, err error) {
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("unable to seek to start of SBOM: %w", err)
	}

	id, version := format.Identify(reader)
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

// writeUnchanged copies the SBOM document as-is to the destination described by the given "<format>[=<path>]"
// output value, falling back to the (deprecated) --file path, and finally to the report bus (STDOUT). When the
// destination is the input file itself there is nothing to do.
func writeUnchanged(output string, defaultFile string, inputPath string, reader io.ReadSeeker) error {
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("unable to seek to start of SBOM: %w", err)
	}

	_, path, _ := strings.Cut(strings.TrimSpace(output), "=")
	if path == "" {
		path = defaultFile
	}

	if path == "" {
		// the report bus only carries strings, so STDOUT output must be materialized in memory
		content, err := io.ReadAll(reader) //nolint:gocritic // the whole SBOM is the report; there is no meaningful bound
		if err != nil {
			return fmt.Errorf("unable to read SBOM: %w", err)
		}
		bus.Report(string(content))
		return nil
	}

	expandedPath, err := homedir.Expand(path)
	if err != nil {
		log.Warnf("could not expand given writer output path=%q: %w", path, err)
		expandedPath = path
	}

	if inputPath != "" && isSameFile(inputPath, expandedPath) {
		log.WithFields("path", expandedPath).Info("output is the input file, leaving it as-is")
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(expandedPath), 0755); err != nil {
		return fmt.Errorf("unable to create report directory: %w", err)
	}

	f, err := os.OpenFile(expandedPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("unable to create report file: %w", err)
	}

	if _, err := io.Copy(f, reader); err != nil {
		_ = f.Close()
		return fmt.Errorf("unable to write report file: %w", err)
	}

	return f.Close()
}

func isSameFile(a, b string) bool {
	aInfo, err := os.Stat(a)
	if err != nil {
		return false
	}
	bInfo, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(aInfo, bInfo)
}

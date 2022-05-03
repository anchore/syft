package convert

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/formats/cyclonedxjson"
	"github.com/anchore/syft/internal/formats/cyclonedxxml"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/spdx22tagvalue"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/hashicorp/go-multierror"
)

var ConvertableFormats = []sbom.FormatID{
	syftjson.ID,
	spdx22json.ID,
	spdx22tagvalue.ID,
	cyclonedxjson.ID,
	cyclonedxxml.ID,
	table.ID,
}

func Run(ctx context.Context, app *config.Application, args []string) error {
	writer, err := makeWriter(app.Outputs, app.File)
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

	sbom, inputFormat, err := syft.Decode(f)
	if err != nil {
		return fmt.Errorf("failed to decode SBOM: %w", err)
	}
	f.Close()

	if !isSupportedFormat(inputFormat.ID()) {
		return fmt.Errorf("cannot convert from %s format", inputFormat.ID())
	}

	return writer.Write(*sbom)
}

func isSupportedFormat(format sbom.FormatID) bool {
	for _, f := range ConvertableFormats {
		if format == f {
			return true
		}
	}

	return false
}

// makeWriter creates a sbom.Writer for output or returns an error. this will either return a valid writer
// or an error but neither both and if there is no error, sbom.Writer.Close() should be called
func makeWriter(outputs []string, defaultFile string) (sbom.Writer, error) {
	outputOptions, formats, err := parseOptions(outputs, defaultFile)
	if err != nil {
		return nil, err
	}

	for _, f := range formats {
		if !isSupportedFormat(f.ID()) {
			return nil, fmt.Errorf("cannot convert to %s", f.ID())
		}
	}

	writer, err := sbom.NewWriter(outputOptions...)
	if err != nil {
		return nil, err
	}

	for _, o := range outputOptions {
		log.Debugf("writer options: %+v", o.Format)
	}

	return writer, nil
}

// parseOptions utility to parse command-line option strings and retain the existing behavior of default format and file
func parseOptions(outputs []string, defaultFile string) (out []sbom.WriterOption, formats []sbom.Format, errs error) {
	// always should have one option -- we generally get the default of "table", but just make sure
	if len(outputs) == 0 {
		outputs = append(outputs, string(table.ID))
	}

	for _, name := range outputs {
		name = strings.TrimSpace(name)

		// split to at most two parts for <format>=<file>
		parts := strings.SplitN(name, "=", 2)

		// the format name is the first part
		name = parts[0]

		// default to the --file or empty string if not specified
		file := defaultFile

		// If a file is specified as part of the output formatName, use that
		if len(parts) > 1 {
			file = parts[1]
		}

		format := syft.FormatByName(name)
		if format == nil {
			errs = multierror.Append(errs, fmt.Errorf("bad output format: '%s'", name))
			continue
		}

		formats = append(formats, format)
		out = append(out, sbom.NewWriterOption(format, file))
	}
	return out, formats, errs
}

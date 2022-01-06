package cmd

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/formats"
	"github.com/anchore/syft/internal/output"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
	"github.com/hashicorp/go-multierror"
)

// makeWriter creates a sbom.Writer for output or returns an error. this will either return a valid writer
// or an error but neither both and if there is no error, sbom.Writer.Close() should be called
func makeWriter(outputs []string, defaultFile string) (sbom.Writer, error) {
	outputOptions, err := parseOptions(outputs, defaultFile)
	if err != nil {
		return nil, err
	}

	writer, err := output.MakeWriter(outputOptions...)
	if err != nil {
		return nil, err
	}

	return writer, nil
}

// parseOptions utility to parse command-line option strings and retain the existing behavior of default format and file
func parseOptions(outputs []string, defaultFile string) (out []output.WriterOption, errs error) {
	// always should have one option -- we generally get the default of "table", but just make sure
	if len(outputs) == 0 {
		outputs = append(outputs, string(format.TableOption))
	}

	for _, name := range outputs {
		name = strings.TrimSpace(name)

		// split to at most two parts for <format>=<file>
		parts := strings.SplitN(name, "=", 2)

		// the format option is the first part
		name = parts[0]

		// default to the --file or empty string if not specified
		file := defaultFile

		// If a file is specified as part of the output option, use that
		if len(parts) > 1 {
			file = parts[1]
		}

		option := format.ParseOption(name)
		if option == format.UnknownFormatOption {
			errs = multierror.Append(errs, fmt.Errorf("bad output format: '%s'", name))
			continue
		}

		encoder := formats.ByOption(option)
		if encoder == nil {
			errs = multierror.Append(errs, fmt.Errorf("unknown format: %s", outputFormat))
			continue
		}

		out = append(out, output.WriterOption{
			Format: *encoder,
			Path:   file,
		})
	}
	return out, errs
}

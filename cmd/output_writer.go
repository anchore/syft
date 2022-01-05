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

// makeWriter creates an sbom.Writer for output or returns an error. this will either return a valid writer
// or an error but neither both and if there is no error, sbom.Writer.Close() should be called
func makeWriter() (sbom.Writer, error) {
	outputOptions, err := parseOptions(appConfig.Output, format.TableOption, appConfig.File)
	if err != nil {
		return nil, err
	}
	writer, err := output.MakeWriter(outputOptions)
	if err != nil {
		return nil, err
	}

	return writer, nil
}

// parseOptions utility to parse command-line option strings and retain the existing behavior of default format and file
func parseOptions(options []string, format format.Option, file string) (out []output.WriterOption, errs error) {
	if len(options) > 0 {
		for _, option := range options {
			option = strings.TrimSpace(option)
			if strings.Contains(option, "=") {
				parts := strings.SplitN(option, "=", 2)
				opt, err := newWriterOption(parts[0], parts[1])
				if err != nil {
					errs = multierror.Append(errs, err)
					continue
				}
				out = append(out, opt)
			} else {
				opt, err := newWriterOption(option, strings.TrimSpace(file))
				if err != nil {
					errs = multierror.Append(errs, err)
					continue
				}
				out = append(out, opt)
			}
		}
	} else {
		opt, err := newWriterOption(string(format), strings.TrimSpace(file))
		if err != nil {
			errs = multierror.Append(errs, err)
		}
		out = append(out, opt)
	}
	return out, errs
}

// newWriterOption validates and parses the format and returns a new writer option with the given format and path
func newWriterOption(outputFormat string, path string) (output.WriterOption, error) {
	formatOption := format.ParseOption(outputFormat)
	if formatOption == format.UnknownFormatOption {
		return output.WriterOption{}, fmt.Errorf("bad --output format value '%s'", outputFormat)
	}

	outputFormatRef := formats.ByOption(formatOption)
	if outputFormatRef == nil {
		return output.WriterOption{}, fmt.Errorf("unknown format: %s", outputFormat)
	}

	return output.WriterOption{
		Format: outputFormatRef,
		Path:   path,
	}, nil
}

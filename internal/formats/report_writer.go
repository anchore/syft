package formats

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
)

type ReportWriter struct {
	Format *format.Format
	Writer io.Writer
	Close  func() error
}

// ReportWriters contains a number of report writers
type ReportWriters struct {
	writers []ReportWriter
}

// Write the provided SBOM to all writers
func (o *ReportWriters) Write(s sbom.SBOM) (errs []error) {
	for _, w := range o.writers {
		err := w.Format.Presenter(s).Present(w.Writer)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// Close any resources, such as open files
func (o *ReportWriters) Close() (errs []error) {
	for _, w := range o.writers {
		if w.Close != nil {
			err := w.Close()
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errs
}

type SBOMWriter struct {
	Writers *ReportWriters
	SBOM    sbom.SBOM
}

// Write writes the SBOM to all writers
func (s *SBOMWriter) Write() []error {
	return s.Writers.Write(s.SBOM)
}

// ParseOptions utility to parse command-line option strings consistently while applying
// the provided default format and file
func ParseOptions(options []string, format format.Option, file string) (out []WriterOption) {
	if len(options) > 0 {
		for _, option := range options {
			option = strings.TrimSpace(option)
			if strings.Contains(option, "=") {
				parts := strings.SplitN(option, "=", 2)
				out = append(out, WriterOption{
					format: parts[0],
					path:   parts[1],
				})
			} else {
				out = append(out, WriterOption{
					format: option,
					path:   strings.TrimSpace(file),
				})
			}
		}
	} else {
		out = append(out, WriterOption{
			format: string(format),
			path:   strings.TrimSpace(file),
		})
	}
	return out
}

type WriterOption struct {
	format string
	path   string
}

// MakeWriters create all report writers from input options, accepts options of the form:
// <format> --or-- <format>=<file>
func MakeWriters(options []WriterOption) (*ReportWriters, error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("no output options provided")
	}

	out := &ReportWriters{}

	for _, option := range options {
		// set the presenter
		formatOption := format.ParseOption(option.format)
		if formatOption == format.UnknownFormatOption {
			return nil, fmt.Errorf("bad --output value '%s'", option)
		}

		outputFormat := ByOption(formatOption)
		if outputFormat == nil {
			return nil, fmt.Errorf("unknown format: %s", option)
		}

		switch len(option.path) {
		case 0:
			out.writers = append(out.writers, ReportWriter{
				Format: outputFormat,
				Writer: os.Stdout,
			})
		default:
			fileOut, err := fileOutput(option.path)
			if err != nil {
				return nil, err
			}
			out.writers = append(out.writers, ReportWriter{
				Format: outputFormat,
				Writer: fileOut,
				Close: func() error {
					return fileOut.Close()
				},
			})
		}
	}

	return out, nil
}

func fileOutput(path string) (*os.File, error) {
	reportFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)

	if err != nil {
		return nil, fmt.Errorf("unable to create report file: %w", err)
	}

	return reportFile, nil
}

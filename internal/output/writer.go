package output

import (
	"fmt"
	"io"
	"os"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
	"github.com/hashicorp/go-multierror"
)

type StreamWriter struct {
	format *format.Format
	out    io.Writer
	close  func() error
}

// Write the provided SBOM to the data stream
func (w *StreamWriter) Write(s sbom.SBOM) error {
	return w.format.Encode(w.out, s)
}

// Close any resources, such as open files
func (w *StreamWriter) Close() error {
	if w.close != nil {
		return w.close()
	}
	return nil
}

// MultiWriter holds a list of child writers to apply all Write and Close operations to
type MultiWriter struct {
	writers []sbom.Writer
}

// Write writes the SBOM to all writers
func (m *MultiWriter) Write(s sbom.SBOM) (errs error) {
	for _, w := range m.writers {
		err := w.Write(s)
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

// Close closes all writers
func (m *MultiWriter) Close() (errs error) {
	for _, w := range m.writers {
		err := w.Close()
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

// WriterOption format and path strings used to create sbom.Writer
type WriterOption struct {
	Format *format.Format
	Path   string
}

// MakeWriter create all report writers from input options, accepts options of the form:
// <format> --or-- <format>=<file>, either a writer or an error is returned, never both
func MakeWriter(options []WriterOption) (sbom.Writer, error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("no output options provided")
	}

	out := &MultiWriter{}

	for _, option := range options {
		switch len(option.Path) {
		case 0:
			out.writers = append(out.writers, &StreamWriter{
				format: option.Format,
				out:    os.Stdout,
			})
		default:
			fileOut, err := fileOutput(option.Path)
			if err != nil {
				// close any previously opened files; we can't really recover from any errors
				_ = out.Close()
				return nil, err
			}
			out.writers = append(out.writers, &StreamWriter{
				format: option.Format,
				out:    fileOut,
				close:  fileOut.Close,
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

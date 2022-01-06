package output

import (
	"fmt"
	"io"
	"os"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
	"github.com/hashicorp/go-multierror"
)

// streamWriter implements sbom.Writer for a given format and io.Writer, also providing a close function for cleanup
type streamWriter struct {
	format format.Format
	out    io.Writer
	close  func() error
}

// Write the provided SBOM to the data stream
func (w *streamWriter) Write(s sbom.SBOM) error {
	return w.format.Encode(w.out, s)
}

// Close any resources, such as open files
func (w *streamWriter) Close() error {
	if w.close != nil {
		return w.close()
	}
	return nil
}

// multiWriter holds a list of child sbom.Writers to apply all Write and Close operations to
type multiWriter struct {
	writers []sbom.Writer
}

// Write writes the SBOM to all writers
func (m *multiWriter) Write(s sbom.SBOM) (errs error) {
	for _, w := range m.writers {
		err := w.Write(s)
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

// Close closes all writers
func (m *multiWriter) Close() (errs error) {
	for _, w := range m.writers {
		err := w.Close()
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

// WriterOption Format and path strings used to create sbom.Writer
type WriterOption struct {
	Format format.Format
	Path   string
}

// MakeWriter create all report writers from input options; if a file is not specified, os.Stdout is used
func MakeWriter(options ...WriterOption) (sbom.Writer, error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("no output options provided")
	}

	out := &multiWriter{}

	for _, option := range options {
		switch len(option.Path) {
		case 0:
			out.writers = append(out.writers, &streamWriter{
				format: option.Format,
				out:    os.Stdout,
			})
		default:
			fileOut, err := os.OpenFile(option.Path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				// close any previously opened files; we can't really recover from any errors
				_ = out.Close()
				return nil, fmt.Errorf("unable to create report file: %w", err)
			}
			out.writers = append(out.writers, &streamWriter{
				format: option.Format,
				out:    fileOut,
				close:  fileOut.Close,
			})
		}
	}

	return out, nil
}

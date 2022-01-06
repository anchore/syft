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
	Format format.Format
	Out    io.Writer
	Closer func() error
}

// Write the provided SBOM to the data stream
func (w *StreamWriter) Write(s sbom.SBOM) error {
	return w.Format.Encode(w.Out, s)
}

// Close any resources, such as open files
func (w *StreamWriter) Close() error {
	if w.Closer != nil {
		return w.Closer()
	}
	return nil
}

// MultiWriter holds a list of child Writers to apply all Write and Close operations to
type MultiWriter struct {
	Writers []sbom.Writer
}

// Write writes the SBOM to all Writers
func (m *MultiWriter) Write(s sbom.SBOM) (errs error) {
	for _, w := range m.Writers {
		err := w.Write(s)
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

// Close closes all Writers
func (m *MultiWriter) Close() (errs error) {
	for _, w := range m.Writers {
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

// MakeWriter create all report Writers from input options; if a file is not specified, os.Stdout is used
func MakeWriter(options ...WriterOption) (sbom.Writer, error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("no output options provided")
	}

	out := &MultiWriter{}

	for _, option := range options {
		switch len(option.Path) {
		case 0:
			out.Writers = append(out.Writers, &StreamWriter{
				Format: option.Format,
				Out:    os.Stdout,
			})
		default:
			fileOut, err := os.OpenFile(option.Path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				// Closer any previously opened files; we can't really recover from any errors
				_ = out.Close()
				return nil, fmt.Errorf("unable to create report file: %w", err)
			}
			out.Writers = append(out.Writers, &StreamWriter{
				Format: option.Format,
				Out:    fileOut,
				Closer: fileOut.Close,
			})
		}
	}

	return out, nil
}

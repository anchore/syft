package sbom

import (
	"fmt"
	"os"
	"path"

	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/syft/internal/log"
)

// multiWriter holds a list of child sbom.Writers to apply all Write and Close operations to
type multiWriter struct {
	writers []Writer
}

// WriterOption Format and path strings used to create sbom.Writer
type WriterOption struct {
	Format Format
	Path   string
}

func NewWriterOption(f Format, p string) WriterOption {
	expandedPath, err := homedir.Expand(p)
	if err != nil {
		log.Warnf("could not expand given writer output path=%q: %w", p, err)
		// ignore errors
		expandedPath = p
	}
	return WriterOption{
		Format: f,
		Path:   expandedPath,
	}
}

// NewWriter create all report writers from input options; if a file is not specified, os.Stdout is used
func NewWriter(options ...WriterOption) (_ Writer, err error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("no output options provided")
	}

	out := &multiWriter{}

	defer func() {
		if err != nil {
			// close any previously opened files; we can't really recover from any errors
			if err := out.Close(); err != nil {
				log.Warnf("unable to close sbom writers: %+v", err)
			}
		}
	}()

	for _, option := range options {
		switch len(option.Path) {
		case 0:
			out.writers = append(out.writers, &streamWriter{
				format: option.Format,
				out:    os.Stdout,
			})
		default:
			// create any missing subdirectories
			dir := path.Dir(option.Path)
			if dir != "" {
				s, err := os.Stat(dir)
				if err != nil {
					err = os.MkdirAll(dir, 0755) // maybe should be os.ModePerm ?
					if err != nil {
						return nil, err
					}
				} else if !s.IsDir() {
					return nil, fmt.Errorf("output path does not contain a valid directory: %s", option.Path)
				}
			}
			fileOut, err := os.OpenFile(option.Path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
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

// Write writes the SBOM to all writers
func (m *multiWriter) Write(s SBOM) (errs error) {
	for _, w := range m.writers {
		err := w.Write(s)
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

// Bytes returns the bytes of the SBOM that would be written
func (m *multiWriter) Bytes(s SBOM) (bytes []byte, err error) {
	for _, w := range m.writers {
		b, err := w.Bytes(s)
		if err != nil {
			return nil, err
		}
		bytes = append(bytes, b...)
	}
	return bytes, nil
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

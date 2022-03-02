package sbom

import (
	"io"
)

// streamWriter implements sbom.Writer for a given format and io.Writer, also providing a close function for cleanup
type streamWriter struct {
	format Format
	out    io.Writer
	close  func() error
}

// Write the provided SBOM to the data stream
func (w *streamWriter) Write(s SBOM) error {
	return w.format.Encode(w.out, s)
}

// Close any resources, such as open files
func (w *streamWriter) Close() error {
	if w.close != nil {
		return w.close()
	}
	return nil
}

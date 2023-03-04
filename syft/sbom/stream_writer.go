package sbom

import (
	"bytes"
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

// Bytes returns the bytes of the SBOM that would be written
func (w *streamWriter) Bytes(s SBOM) ([]byte, error) {
	var buffer bytes.Buffer
	err := w.format.Encode(&buffer, s)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// Close any resources, such as open files
func (w *streamWriter) Close() error {
	if w.close != nil {
		return w.close()
	}
	return nil
}

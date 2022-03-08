package syft

import (
	"bytes"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

// Encode takes all SBOM elements and a format option and encodes an SBOM document.
func Encode(s sbom.SBOM, f sbom.Format) ([]byte, error) {
	buff := bytes.Buffer{}

	if err := f.Encode(&buff, s); err != nil {
		return nil, fmt.Errorf("unable to encode sbom: %w", err)
	}

	return buff.Bytes(), nil
}

// Decode takes a reader for an SBOM and generates all internal SBOM elements.
func Decode(reader io.Reader) (*sbom.SBOM, sbom.Format, error) {
	by, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read sbom: %w", err)
	}

	f := IdentifyFormat(by)
	if f == nil {
		return nil, nil, fmt.Errorf("unable to identify format")
	}

	s, err := f.Decode(bytes.NewReader(by))
	return s, f, err
}

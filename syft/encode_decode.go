package syft

import (
	"bytes"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/syft/internal/formats"
	"github.com/anchore/syft/syft/format"
)

// Encode takes all SBOM elements and a format option and encodes an SBOM document.
func Encode(s sbom.SBOM, appConfig interface{}, option format.Option) ([]byte, error) {
	f := formats.ByOption(option)
	if f == nil {
		return nil, fmt.Errorf("unsupported format: %+v", option)
	}
	buff := bytes.Buffer{}

	if err := f.Encode(&buff, s, appConfig); err != nil {
		return nil, fmt.Errorf("unable to encode sbom: %w", err)
	}

	return buff.Bytes(), nil
}

// Decode takes a reader for an SBOM and generates all internal SBOM elements.
func Decode(reader io.Reader) (*sbom.SBOM, format.Option, error) {
	by, err := io.ReadAll(reader)
	if err != nil {
		return nil, format.UnknownFormatOption, fmt.Errorf("unable to read sbom: %w", err)
	}

	f, err := formats.Identify(by)
	if err != nil {
		return nil, format.UnknownFormatOption, fmt.Errorf("unable to detect format: %w", err)
	}
	if f == nil {
		return nil, format.UnknownFormatOption, fmt.Errorf("unable to identify format")
	}
	s, err := f.Decode(bytes.NewReader(by))
	return s, f.Option, err
}

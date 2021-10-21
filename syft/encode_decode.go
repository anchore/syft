package syft

import (
	"bytes"
	"fmt"
	"io"

	"github.com/anchore/syft/internal/formats"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Encode takes all SBOM elements and a format option and encodes an SBOM document.
// TODO: encapsulate input data into common sbom document object
func Encode(catalog *pkg.Catalog, metadata *source.Metadata, dist *distro.Distro, scope source.Scope, option format.Option) ([]byte, error) {
	f := formats.ByOption(option)
	if f == nil {
		return nil, fmt.Errorf("unsupported format: %+v", option)
	}
	buff := bytes.Buffer{}

	if err := f.Encode(&buff, catalog, dist, metadata, scope); err != nil {
		return nil, fmt.Errorf("unable to encode sbom: %w", err)
	}

	return buff.Bytes(), nil
}

// Decode takes a reader for an SBOM and generates all internal SBOM elements.
// TODO: encapsulate return data into common sbom document object
func Decode(reader io.Reader) (*pkg.Catalog, *source.Metadata, *distro.Distro, source.Scope, format.Option, error) {
	by, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, nil, source.UnknownScope, format.UnknownFormatOption, fmt.Errorf("unable to read sbom: %w", err)
	}

	f, err := formats.Identify(by)
	if err != nil {
		return nil, nil, nil, source.UnknownScope, format.UnknownFormatOption, fmt.Errorf("unable to detect format: %w", err)
	}
	if f == nil {
		return nil, nil, nil, source.UnknownScope, format.UnknownFormatOption, fmt.Errorf("unable to identify format")
	}
	c, m, d, s, err := f.Decode(bytes.NewReader(by))
	return c, m, d, s, f.Option, err
}

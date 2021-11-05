package format

import (
	"io"

	"github.com/anchore/syft/syft/sbom"
)

// Decoder is a function that can convert an SBOM document of a specific format from a reader into Syft native objects.
type Decoder func(reader io.Reader) (*sbom.SBOM, error)

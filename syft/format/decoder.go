package format

import (
	"io"

	"github.com/anchore/syft/syft/sbom"
)

// Decoder is an object that can convert an SBOM document of a specific format from a reader into Syft native objects.
type Decoder interface {
	Decode(reader io.Reader) (*sbom.SBOM, error)
}

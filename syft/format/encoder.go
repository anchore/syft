package format

import (
	"io"

	"github.com/anchore/syft/syft/sbom"
)

// Encoder is a function that can transform Syft native objects from an SBOM document of a specific format written to the given writer.
type Encoder interface {
	Encode(io.Writer, sbom.SBOM) error
}

package format

import (
	"io"

	"github.com/anchore/syft/syft/sbom"
)

// Encoder is a function that can transform Syft native objects into an SBOM document of a specific format written to the given writer.
type Encoder func(io.Writer, sbom.SBOM, interface{}) error

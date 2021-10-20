package format

import (
	"io"

	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Encoder is a function that can transform Syft native objects into an SBOM document of a specific format written to the given writer.
type Encoder func(io.Writer, *pkg.Catalog, *source.Metadata, *distro.Distro, source.Scope) error

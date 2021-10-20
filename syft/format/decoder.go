package format

import (
	"io"

	"github.com/anchore/syft/syft/distro"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Decoder is a function that can convert an SBOM document of a specific format from a reader into Syft native objects.
type Decoder func(reader io.Reader) (*pkg.Catalog, *source.Metadata, *distro.Distro, source.Scope, error)

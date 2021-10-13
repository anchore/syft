package format

import (
	"io"

	"github.com/anchore/syft/syft/distro"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type Decoder func(reader io.Reader) (*pkg.Catalog, *source.Metadata, *distro.Distro, source.Scope, error)

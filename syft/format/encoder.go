package format

import (
	"io"

	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type Encoder func(io.Writer, *pkg.Catalog, *source.Metadata, *distro.Distro, source.Scope) error

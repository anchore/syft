package format

import (
	"io"

	"github.com/anchore/syft/syft/distro"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type Presenter struct {
	catalog     *pkg.Catalog
	srcMetadata *source.Metadata
	distro      *distro.Distro
	scope       source.Scope
	encoder     Encoder
}

func NewPresenter(encoder Encoder, catalog *pkg.Catalog, srcMetadata *source.Metadata, d *distro.Distro, scope source.Scope) *Presenter {
	return &Presenter{
		catalog:     catalog,
		srcMetadata: srcMetadata,
		distro:      d,
		encoder:     encoder,
		scope:       scope,
	}
}

func (pres *Presenter) Present(output io.Writer) error {
	return pres.encoder(output, pres.catalog, pres.srcMetadata, pres.distro, pres.scope)
}

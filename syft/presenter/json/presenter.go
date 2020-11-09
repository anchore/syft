package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

type Presenter struct {
	catalog *pkg.Catalog
	scope   scope.Scope
	distro  distro.Distro
}

func NewPresenter(catalog *pkg.Catalog, s scope.Scope, d distro.Distro) *Presenter {
	return &Presenter{
		catalog: catalog,
		scope:   s,
		distro:  d,
	}
}

func (pres *Presenter) Present(output io.Writer) error {
	doc, err := NewDocument(pres.catalog, pres.scope, pres.distro)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}

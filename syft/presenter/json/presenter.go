package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

type Presenter struct {
	catalog *pkg.Catalog
	scope   scope.Scope
}

func NewPresenter(catalog *pkg.Catalog, s scope.Scope) *Presenter {
	return &Presenter{
		catalog: catalog,
		scope:   s,
	}
}

func (pres *Presenter) Present(output io.Writer) error {
	doc, err := NewDocument(pres.catalog, pres.scope)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}

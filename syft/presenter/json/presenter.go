package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Presenter is a JSON presentation object for the syft results
type Presenter struct {
	catalog     *pkg.Catalog
	srcMetadata source.Metadata
	distro      *distro.Distro
}

// NewPresenter creates a new JSON presenter object for the given cataloging results.
func NewPresenter(catalog *pkg.Catalog, s source.Metadata, d *distro.Distro) *Presenter {
	return &Presenter{
		catalog:     catalog,
		srcMetadata: s,
		distro:      d,
	}
}

// Present the catalog results to the given writer.
func (pres *Presenter) Present(output io.Writer) error {
	doc, err := NewDocument(pres.catalog, pres.srcMetadata, pres.distro)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}

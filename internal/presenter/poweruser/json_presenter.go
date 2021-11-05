package poweruser

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

// JSONPresenter is a JSON presentation object for the syft results
type JSONPresenter struct {
	sbom   sbom.SBOM
	config interface{}
}

// NewJSONPresenter creates a new JSON presenter object for the given cataloging results.
func NewJSONPresenter(s sbom.SBOM, appConfig interface{}) *JSONPresenter {
	return &JSONPresenter{
		sbom:   s,
		config: appConfig,
	}
}

// Present the PackageCatalog results to the given writer.
func (p *JSONPresenter) Present(output io.Writer) error {
	doc, err := NewJSONDocument(p.sbom, p.config)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}

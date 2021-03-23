package poweruser

import (
	"encoding/json"
	"io"
)

// JSONPresenter is a JSON presentation object for the syft results
type JSONPresenter struct {
	config JSONDocumentConfig
}

// NewJSONPresenter creates a new JSON presenter object for the given cataloging results.
func NewJSONPresenter(config JSONDocumentConfig) *JSONPresenter {
	return &JSONPresenter{
		config: config,
	}
}

// Present the PackageCatalog results to the given writer.
func (p *JSONPresenter) Present(output io.Writer) error {
	doc, err := NewJSONDocument(p.config)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}

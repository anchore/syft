package poweruser

import (
	"github.com/anchore/syft/internal/presenter/packages"
)

type JSONDocument struct {
	// note: poweruser.JSONDocument is meant to always be a superset of packages.JSONDocument, any additional fields
	// here should be optional by supplying "omitempty" on these fields hint to the jsonschema generator to not
	// require these fields. As an accepted rule in this repo all collections should still be initialized in the
	// context of being used in a JSON document.
	FileMetadata []JSONFileMetadata `json:"fileMetadata,omitempty"`
	packages.JSONDocument
}

// NewJSONDocument creates and populates a new JSON document struct from the given cataloging results.
func NewJSONDocument(config JSONDocumentConfig) (JSONDocument, error) {
	pkgsDoc, err := packages.NewJSONDocument(config.PackageCatalog, config.SourceMetadata, config.Distro, config.ApplicationConfig.Package.Cataloger.ScopeOpt, config.ApplicationConfig)
	if err != nil {
		return JSONDocument{}, err
	}

	fileMetadata, err := NewJSONFileMetadata(config.FileMetadata, config.FileDigests)
	if err != nil {
		return JSONDocument{}, err
	}

	return JSONDocument{
		FileMetadata: fileMetadata,
		JSONDocument: pkgsDoc,
	}, nil
}

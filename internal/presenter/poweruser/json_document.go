package poweruser

import (
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/syftjson/model"
)

type JSONDocument struct {
	// note: poweruser.JSONDocument is meant to always be a superset of packages.Document, any additional fields
	// here should be optional by supplying "omitempty" on these fields hint to the jsonschema generator to not
	// require these fields. As an accepted rule in this repo all collections should still be initialized in the
	// context of being used in a JSON document.
	FileClassifications []JSONFileClassifications `json:"fileClassifications,omitempty"` // note: must have omitempty
	FileContents        []JSONFileContents        `json:"fileContents,omitempty"`        // note: must have omitempty
	FileMetadata        []JSONFileMetadata        `json:"fileMetadata,omitempty"`        // note: must have omitempty
	Secrets             []JSONSecrets             `json:"secrets,omitempty"`             // note: must have omitempty
	model.Document
}

// NewJSONDocument creates and populates a new JSON document struct from the given cataloging results.
func NewJSONDocument(config JSONDocumentConfig) (JSONDocument, error) {
	pkgsDoc := syftjson.ToFormatModel(config.PackageCatalog, &config.SourceMetadata, config.Distro, config.ApplicationConfig)

	fileMetadata, err := NewJSONFileMetadata(config.FileMetadata, config.FileDigests)
	if err != nil {
		return JSONDocument{}, err
	}

	return JSONDocument{
		FileClassifications: NewJSONFileClassifications(config.FileClassifications),
		FileContents:        NewJSONFileContents(config.FileContents),
		FileMetadata:        fileMetadata,
		Secrets:             NewJSONSecrets(config.Secrets),
		Document:            pkgsDoc,
	}, nil
}

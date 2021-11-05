package poweruser

import (
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/syft/sbom"
)

type JSONDocument struct {
	// note: poweruser.JSONDocument is meant to always be a superset of packages.JSONDocument, any additional fields
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
func NewJSONDocument(s sbom.SBOM, appConfig interface{}) (JSONDocument, error) {
	fileMetadata, err := NewJSONFileMetadata(s.Artifacts.FileMetadata, s.Artifacts.FileDigests)
	if err != nil {
		return JSONDocument{}, err
	}

	return JSONDocument{
		FileClassifications: NewJSONFileClassifications(s.Artifacts.FileClassifications),
		FileContents:        NewJSONFileContents(s.Artifacts.FileContents),
		FileMetadata:        fileMetadata,
		Secrets:             NewJSONSecrets(s.Artifacts.Secrets),
		Document:            syftjson.ToFormatModel(s, appConfig),
	}, nil
}

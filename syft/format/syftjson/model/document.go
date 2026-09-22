package model

import (
	"encoding/json"
	"fmt"
)

// Field order matters: encoding/json writes struct fields in declaration order, and Schema must remain the last
// field so that the schema block is always the final key of the encoded document. Format identification relies on
// finding the schema block by reading only the tail of a (potentially very large) document; moving Schema earlier
// would not break decoding but would silently force a full parse of the whole document to identify it.
//
// (This block is deliberately separated from the doc comment below: the JSON schema generator lifts doc comments
// into schema descriptions, and changing the description would alter the published schema.)

// Document represents the syft cataloging findings as a JSON document
type Document struct {
	Artifacts             []Package      `json:"artifacts"` // Artifacts is the list of packages discovered and placed into the catalog
	ArtifactRelationships []Relationship `json:"artifactRelationships"`
	Files                 []File         `json:"files,omitempty"` // note: must have omitempty
	Source                Source         `json:"source"`          // Source represents the original object that was cataloged
	Distro                LinuxRelease   `json:"distro"`          // Distro represents the Linux distribution that was detected from the source
	Descriptor            Descriptor     `json:"descriptor"`      // Descriptor is a block containing self-describing information about syft
	Schema                Schema         `json:"schema"`          // Schema is a block reserved for defining the version for the shape of this JSON document and where to find the schema document to validate the shape
}

func (d *Document) UnmarshalJSON(data []byte) error {
	type Alias Document
	aux := (*Alias)(d)

	if err := json.Unmarshal(data, aux); err != nil {
		return fmt.Errorf("could not unmarshal syft JSON document: %w", err)
	}

	// in previous versions of anchorectl, the file modes were stored as decimal values instead of octal.
	if d.Schema.Version == "1.0.0" && d.Descriptor.Name == "anchorectl" {
		// convert all file modes from decimal to octal
		for i := range d.Files {
			d.Files[i].Metadata.Mode = convertBase10ToBase8(d.Files[i].Metadata.Mode)
		}
	}

	return nil
}

// Descriptor identifies the tool that generated this SBOM document, including its name, version, and configuration used during catalog generation.
type Descriptor struct {
	// Name is the name of the tool that generated this SBOM (e.g., "syft").
	Name string `json:"name"`

	// Version is the version of the tool that generated this SBOM.
	Version string `json:"version"`

	// Configuration contains the tool configuration used during SBOM generation.
	Configuration any `json:"configuration,omitempty"`
}

// Schema specifies the JSON schema version and URL reference that defines the structure and validation rules for this document format.
type Schema struct {
	// Version is the JSON schema version for this document format.
	Version string `json:"version"`

	// URL is the URL to the JSON schema definition document.
	URL string `json:"url"`
}

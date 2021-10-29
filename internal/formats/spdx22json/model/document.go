package model

// derived from:
// - https://spdx.github.io/spdx-spec/appendix-III-RDF-data-model-implementation-and-identifier-syntax/
// - https://github.com/spdx/spdx-spec/blob/v2.2/schemas/spdx-schema.json
// - https://github.com/spdx/spdx-spec/tree/v2.2/ontology

type Document struct {
	Element
	SPDXVersion string `json:"spdxVersion"`
	// One instance is required for each SPDX file produced. It provides the necessary information for forward
	// and backward compatibility for processing tools.
	CreationInfo CreationInfo `json:"creationInfo"`
	// 2.2: Data License; should be "CC0-1.0"
	// Cardinality: mandatory, one
	// License expression for dataLicense.  Compliance with the SPDX specification includes populating the SPDX
	// fields therein with data related to such fields (\"SPDX-Metadata\"). The SPDX specification contains numerous
	// fields where an SPDX document creator may provide relevant explanatory text in SPDX-Metadata. Without
	// opining on the lawfulness of \"database rights\" (in jurisdictions where applicable), such explanatory text
	// is copyrightable subject matter in most Berne Convention countries. By using the SPDX specification, or any
	// portion hereof, you hereby agree that any copyright rights (as determined by your jurisdiction) in any
	// SPDX-Metadata, including without limitation explanatory text, shall be subject to the terms of the Creative
	// Commons CC0 1.0 Universal license. For SPDX-Metadata not containing any copyright rights, you hereby agree
	// and acknowledge that the SPDX-Metadata is provided to you \"as-is\" and without any representations or
	// warranties of any kind concerning the SPDX-Metadata, express, implied, statutory or otherwise, including
	// without limitation warranties of title, merchantability, fitness for a particular purpose, non-infringement,
	// or the absence of latent or other defects, accuracy, or the presence or absence of errors, whether or not
	// discoverable, all to the greatest extent permissible under applicable law.
	DataLicense string `json:"dataLicense"`
	// Information about an external SPDX document reference including the checksum. This allows for verification of the external references.
	ExternalDocumentRefs []ExternalDocumentRef `json:"externalDocumentRefs,omitempty"`
	// Indicates that a particular ExtractedLicensingInfo was defined in the subject SpdxDocument.
	HasExtractedLicensingInfos []HasExtractedLicensingInfo `json:"hasExtractedLicensingInfos,omitempty"`
	// note: found in example documents from SPDX, but not in the JSON schema. See https://spdx.github.io/spdx-spec/2-document-creation-information/#25-spdx-document-namespace
	DocumentNamespace string `json:"documentNamespace"`
	// note: found in example documents from SPDX, but not in the JSON schema
	// DocumentDescribes []string  `json:"documentDescribes"`
	Packages []Package `json:"packages"`
	// Files referenced in the SPDX document
	Files []File `json:"files,omitempty"`
	// Snippets referenced in the SPDX document
	Snippets []Snippet `json:"snippets,omitempty"`
	// Relationships referenced in the SPDX document
	Relationships []Relationship `json:"relationships,omitempty"`
}

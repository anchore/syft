package model

type ExternalDocumentRef struct {
	// externalDocumentId is a string containing letters, numbers, ., - and/or + which uniquely identifies an external document within this document.
	ExternalDocumentID string   `json:"externalDocumentId"`
	Checksum           Checksum `json:"checksum"`
	// SPDX ID for SpdxDocument.  A propoerty containing an SPDX document.
	SpdxDocument string `json:"spdxDocument"`
}

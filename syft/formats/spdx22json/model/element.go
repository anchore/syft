package model

type Element struct {
	SPDXID string `json:"SPDXID"`
	// Identify name of this SpdxElement.
	Name string `json:"name,omitempty"`
	// Relationships referenced in the SPDX document
	Relationships []Relationship `json:"relationships,omitempty"`
	// Provide additional information about an SpdxElement.
	Annotations []Annotation `json:"annotations,omitempty"`
	Comment     string       `json:"comment,omitempty"`
}

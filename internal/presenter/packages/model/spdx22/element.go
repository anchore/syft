package spdx22

type Element struct {
	SPDXID string `json:"SPDXID"`
	// Provide additional information about an SpdxElement.
	Annotations []Annotation `json:"annotations,omitempty"`
	Comment     string       `json:"comment,omitempty"`
	// Identify name of this SpdxElement.
	Name string `json:"name"`
	// Relationships referenced in the SPDX document
	Relationships []Relationship `json:"relationships,omitempty"`
}

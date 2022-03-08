package model

import "github.com/anchore/syft/internal/formats/common/spdxhelpers"

type Relationship struct {
	// Id to which the SPDX element is related
	SpdxElementID string `json:"spdxElementId"`
	// Describes the type of relationship between two SPDX elements.
	RelationshipType spdxhelpers.RelationshipType `json:"relationshipType"`
	// SPDX ID for SpdxElement.  A related SpdxElement.
	RelatedSpdxElement string `json:"relatedSpdxElement"`
	Comment            string `json:"comment,omitempty"`
}

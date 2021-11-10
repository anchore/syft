package artifact

const (
	// OwnershipByFileOverlapRelationship indicates that the parent package claims ownership of a child package since
	// the parent metadata indicates overlap with a location that a cataloger found the child package by. This is
	// by definition a package-to-package relationship and is created only after all package cataloging has been completed.
	OwnershipByFileOverlapRelationship RelationshipType = "ownership-by-file-overlap"
)

type RelationshipType string

type Relationship struct {
	From Identifiable     `json:"from"`
	To   Identifiable     `json:"to"`
	Type RelationshipType `json:"type"`
	Data interface{}      `json:"data,omitempty"`
}

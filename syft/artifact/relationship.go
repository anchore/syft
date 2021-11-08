package artifact

const (
	// OwnershipByFileOverlapRelationship indicates that the parent package owns the child package made evident by the set of provided files
	OwnershipByFileOverlapRelationship RelationshipType = "ownership-by-file-overlap"
)

type RelationshipType string

type Relationship struct {
	From Identifiable     `json:"from"`
	To   Identifiable     `json:"to"`
	Type RelationshipType `json:"type"`
	Data interface{}      `json:"data,omitempty"`
}

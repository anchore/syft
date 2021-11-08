package artifact

const (
	// OwnershipByFileOverlapRelationship indicates that the parent package owns the child package made evident by the set of provided files
	OwnershipByFileOverlapRelationship RelationshipType = "ownership-by-file-overlap"
)

type RelationshipType string

type Relationship struct {
	From ID
	To   ID
	Type RelationshipType
	Data interface{}
}

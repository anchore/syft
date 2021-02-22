package pkg

const (
	// OwnershipByFiles indicates that the parent package owns the child package made evident by the set of provided files
	OwnershipByFilesRelationship RelationshipType = "ownership-by-files"
)

type RelationshipType string

type Relationship struct {
	Parent   ID
	Child    ID
	Type     RelationshipType
	Metadata interface{}
}

func NewRelationships(catalog *Catalog) []Relationship {
	return ownershipByFilesRelationships(catalog)
}

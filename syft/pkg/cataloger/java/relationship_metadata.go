package java

// DependencyRelationshipData carries hierarchical dependency information through the
// deferred parent resolution pipeline. Stored in artifact.Relationship.Data.
type DependencyRelationshipData struct {
	Depth              int    `json:"depth"`
	Scope              string `json:"scope,omitempty"`
	IsDirectDependency bool   `json:"isDirectDependency"`
	IntendedParentID   string `json:"intendedParentId,omitempty"`
}

func NewDependencyRelationshipData(depth int, scope string) DependencyRelationshipData {
	return DependencyRelationshipData{
		Depth:              depth,
		Scope:              scope,
		IsDirectDependency: depth == 0,
	}
}

func NewDependencyRelationshipDataWithParent(depth int, scope string, intendedParentID string) DependencyRelationshipData {
	return DependencyRelationshipData{
		Depth:              depth,
		Scope:              scope,
		IsDirectDependency: depth == 0,
		IntendedParentID:   intendedParentID,
	}
}

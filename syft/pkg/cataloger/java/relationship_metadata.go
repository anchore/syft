package java

// DependencyRelationshipData holds metadata about a dependency relationship that is
// attached to artifact.Relationship.Data for enriched Syft JSON output.
type dependencyRelationshipData struct {
	Depth              int    `json:"depth"`
	Scope              string `json:"scope,omitempty"`
	IsDirectDependency bool   `json:"isDirectDependency"`
	IntendedParentID   string `json:"intendedParentId,omitempty"`
}

// NewDependencyRelationshipData creates relationship metadata with depth and scope.
func newDependencyRelationshipData(depth int, scope string) dependencyRelationshipData {
	return dependencyRelationshipData{
		Depth:              depth,
		Scope:              scope,
		IsDirectDependency: depth == 0,
	}
}

// NewDependencyRelationshipDataWithParent creates relationship metadata that includes
// an intended parent ID for deferred resolution by the post-processor.
func newDependencyRelationshipDataWithParent(depth int, scope string, intendedParentID string) dependencyRelationshipData {
	return dependencyRelationshipData{
		Depth:              depth,
		Scope:              scope,
		IsDirectDependency: depth == 0,
		IntendedParentID:   intendedParentID,
	}
}

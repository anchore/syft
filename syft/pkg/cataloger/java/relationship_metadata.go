package java

import "fmt"

// DependencyRelationshipData holds metadata about a dependency relationship that is
// attached to artifact.Relationship.Data for enriched Syft JSON output.
type DependencyRelationshipData struct {
	Depth              int    `json:"depth"`
	Scope              string `json:"scope,omitempty"`
	IsDirectDependency bool   `json:"isDirectDependency"`
	IntendedParentID   string `json:"intendedParentId,omitempty"`
}

// NewDependencyRelationshipData creates relationship metadata with depth and scope.
func NewDependencyRelationshipData(depth int, scope string) DependencyRelationshipData {
	return DependencyRelationshipData{
		Depth:              depth,
		Scope:              scope,
		IsDirectDependency: depth == 0,
	}
}

// NewDependencyRelationshipDataWithParent creates relationship metadata that includes
// an intended parent ID for deferred resolution by the post-processor.
func NewDependencyRelationshipDataWithParent(depth int, scope string, intendedParentID string) DependencyRelationshipData {
	return DependencyRelationshipData{
		Depth:              depth,
		Scope:              scope,
		IsDirectDependency: depth == 0,
		IntendedParentID:   intendedParentID,
	}
}

// IntendedParentMavenID returns the formatted intended parent ID string for display/logging.
func (d DependencyRelationshipData) IntendedParentMavenID() string {
	if d.IntendedParentID == "" {
		return ""
	}
	return fmt.Sprintf("intendedParent=%s", d.IntendedParentID)
}

package artifact

const (
	// OwnershipByFileOverlapRelationship (supports package-to-package linkages) indicates that the parent package
	// claims ownership of a child package since the parent metadata indicates overlap with a location that a
	// cataloger found the child package by. This relationship must be created only after all package cataloging
	// has been completed.
	OwnershipByFileOverlapRelationship RelationshipType = "ownership-by-file-overlap"

	// ContainsRelationship (supports any-to-any linkages) is a proxy for the SPDX 2.2 CONTAINS relationship.
	ContainsRelationship RelationshipType = "contains"

	// RuntimeDependencyOfRelationship is a proxy for the SPDX 2.2.1 RUNTIME_DEPENDENCY_OF relationship.
	RuntimeDependencyOfRelationship RelationshipType = "runtime-dependency-of"

	// DevDependencyOfRelationship is a proxy for the SPDX 2.2.1 DEV_DEPENDENCY_OF relationship.
	DevDependencyOfRelationship RelationshipType = "dev-dependency-of"

	// BuildDependencyOfRelationship is a proxy for the SPDX 2.2.1 BUILD_DEPENDENCY_OF relationship.
	BuildDependencyOfRelationship RelationshipType = "build-dependency-of"

	// DependencyOfRelationship is a proxy for the SPDX 2.2.1 DEPENDENCY_OF	relationship.
	DependencyOfRelationship RelationshipType = "dependency-of"
)

type RelationshipType string

type Relationship struct {
	From Identifiable
	To   Identifiable
	Type RelationshipType
	Data interface{}
}

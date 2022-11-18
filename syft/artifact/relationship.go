package artifact

const (
	// OwnershipByFileOverlapRelationship (supports package-to-package linkages) indicates that the parent package
	// claims ownership of a child package since the parent metadata indicates overlap with a location that a
	// cataloger found the child package by. This relationship must be created only after all package cataloging
	// has been completed.
	OwnershipByFileOverlapRelationship RelationshipType = "ownership-by-file-overlap"

	// ContainsRelationship (supports any-to-any linkages) is a proxy for the SPDX 2.2 CONTAINS relationship.
	ContainsRelationship RelationshipType = "contains"

	// DependencyOfRelationship is a proxy for the SPDX 2.2.1 DEPENDENCY_OF	relationship.
	DependencyOfRelationship RelationshipType = "dependency-of"

	// DescribedByRelationship is a proxy for the SPDX 2.2.2 DESCRIBED_BY relationship.
	DescribedByRelationship RelationshipType = "described-by"
)

type RelationshipType string

type Relationship struct {
	From Identifiable
	To   Identifiable
	Type RelationshipType
	Data interface{}
}

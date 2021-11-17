package artifact

const (
	// OwnershipByFileOverlapRelationship (supports package-to-package linkages) indicates that the parent package
	// claims ownership of a child package since the parent metadata indicates overlap with a location that a
	// cataloger found the child package by. This relationship must be created only after all package cataloging
	// has been completed.
	OwnershipByFileOverlapRelationship RelationshipType = "ownership-by-file-overlap"

	// PackageOfRelationship (supports any-to-package linkages) is a proxy for the SPDX 2.2 PACKAGE_OF
	// relationship which is defined as: "to be used when artifact X is used as a package as part of package Y"
	PackageOfRelationship RelationshipType = "package-of"
)

type RelationshipType string

type Relationship struct {
	From Identifiable
	To   Identifiable
	Type RelationshipType
	Data interface{}
}

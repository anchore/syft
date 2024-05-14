package cmptest

import (
	"github.com/sanity-io/litter"

	"github.com/anchore/syft/syft/artifact"
)

type RelationshipComparer func(x, y artifact.Relationship) bool

var relationshipStringer = litter.Options{
	Compact:           true,
	StripPackageNames: false,
	HidePrivateFields: true, // we want to ignore package IDs
	HideZeroValues:    true,
	StrictGo:          true,
	//FieldExclusions: ...  // these can be added for future values that need to be ignored
	//FieldFilter: ...
}

func DefaultRelationshipComparer(x, y artifact.Relationship) bool {
	// we just need a stable sort, the ordering does not need to be sensible
	xStr := relationshipStringer.Sdump(x)
	yStr := relationshipStringer.Sdump(y)
	return xStr < yStr
}

package cmptest

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/sort"
)

func DefaultRelationshipComparer(x, y artifact.Relationship) bool {
	return sort.Less(x, y)
}

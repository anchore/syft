package cmptest

import (
	"reflect"

	"github.com/sanity-io/litter"

	"github.com/anchore/syft/syft/artifact"
)

type RelationshipComparer func(x, y artifact.Relationship) bool

var dataStringer = litter.Options{
	Compact:           true,
	StripPackageNames: false,
	//HidePrivateFields: true, // we want to ignore package IDs
	HideZeroValues: true,
	StrictGo:       true,
	//FieldExclusions: ...  // these can be added for future values that need to be ignored
	//FieldFilter: ...
}

func DefaultRelationshipComparer(x, y artifact.Relationship) bool {
	if reflect.ValueOf(x.From).Type().Name() < reflect.ValueOf(y.From).Type().Name() {
		return true
	}
	if x.From.ID() < y.From.ID() {
		return true
	}
	if reflect.ValueOf(x.To).Type().Name() < reflect.ValueOf(y.To).Type().Name() {
		return true
	}
	if x.To.ID() < y.To.ID() {
		return true
	}
	if x.Type < y.Type {
		return true
	}
	if x.Data == nil && y.Data == nil {
		return false
	}
	if x.Data == nil {
		return true
	}
	if y.Data == nil {
		return true
	}
	if reflect.ValueOf(x.Data).Type().Name() < reflect.ValueOf(y.Data).Type().Name() {
		return true
	}
	// we just need a stable sort, the ordering does not need to be sensible
	xStr := dataStringer.Sdump(x.Data)
	yStr := dataStringer.Sdump(y.Data)
	return xStr < yStr
}

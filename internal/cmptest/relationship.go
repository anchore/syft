package cmptest

import (
	"github.com/sanity-io/litter"
	"reflect"

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

func DefaultRelationshipComparer(x, y artifact.Relationship) int {
	if x.Type < y.Type {
		return -1
	}
	if x.Type > y.Type {
		return 1
	}

	{
		xFrom := reflect.ValueOf(x.From).Type().Name()
		yFrom := reflect.ValueOf(y.From).Type().Name()
		if xFrom < yFrom {
			return -1
		}
		if xFrom > yFrom {
			return 1
		}
	}
	{
		xFrom := x.From.ID()
		yFrom := y.From.ID()
		if xFrom < yFrom {
			return -1
		}
		if xFrom > yFrom {
			return 1
		}
	}
	{
		xTo := reflect.ValueOf(x.To).Type().Name()
		yTo := reflect.ValueOf(y.To).Type().Name()
		if xTo < yTo {
			return -1
		}
		if xTo > yTo {
			return 1
		}
	}
	{
		xTo := x.To.ID()
		yTo := y.To.ID()
		if xTo < yTo {
			return -1
		}
		if xTo > yTo {
			return 1
		}
	}

	if x.Data == nil && y.Data == nil {
		return 0
	}
	if x.Data == nil {
		return -1
	}
	if y.Data == nil {
		return 1
	}

	{
		xData := reflect.ValueOf(x.Data).Type().Name()
		yData := reflect.ValueOf(y.Data).Type().Name()
		if xData < yData {
			return -1
		}
		if xData > yData {
			return 1
		}
	}
	// we just need a stable sort, the ordering does not need to be sensible
	xStr := dataStringer.Sdump(x.Data)
	yStr := dataStringer.Sdump(y.Data)
	if xStr < yStr {
		return -1
	}
	if xStr > yStr {
		return 1
	}
	return 0
}

package source

import (
	"github.com/anchore/syft/syft/sort"
	"reflect"
)

// Description represents any static source data that helps describe "what" was cataloged.
type Description struct {
	ID       string `hash:"ignore"` // the id generated from the parent source struct
	Name     string `hash:"ignore"`
	Version  string `hash:"ignore"`
	Metadata sort.TryComparable
}

func (desc Description) Compare(other Description) int {
	if i := sort.CompareOrd(desc.ID, other.ID); i != 0 {
		return i
	}
	if i := sort.CompareOrd(desc.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(desc.Version, other.Version); i != 0 {
		return i
	}
	if canBeCompared, i := desc.Metadata.TryCompare(other.Metadata); canBeCompared {
		return i
	}
	return sort.CompareOrd(reflect.ValueOf(desc.Metadata).Type().Name(), reflect.ValueOf(other.Metadata).Type().Name())
}

func (desc Description) TryCompare(other any) (bool, int) {
	if other, exists := other.(Description); exists {
		return true, sort.Compare(desc, other)
	}
	return false, 0
}

package internal

import (
	"sort"

	"github.com/mitchellh/hashstructure/v2"
)

// StringSet represents a set of string types.
type StringSet map[string]struct{}

// NewStringSet creates a new empty StringSet.
func NewStringSet(start ...string) StringSet {
	ret := make(StringSet)
	for _, s := range start {
		ret.Add(s)
	}
	return ret
}

// Add a string to the set.
func (s StringSet) Add(i ...string) {
	for _, v := range i {
		s[v] = struct{}{}
	}
}

// Remove a string from the set.
func (s StringSet) Remove(i string) {
	delete(s, i)
}

// Contains indicates if the given string is contained within the set.
func (s StringSet) Contains(i string) bool {
	_, ok := s[i]
	return ok
}

// ToSlice returns a sorted slice of strings that are contained within the set.
func (s StringSet) ToSlice() []string {
	ret := make([]string, len(s))
	idx := 0
	for v := range s {
		ret[idx] = v
		idx++
	}
	sort.Strings(ret)
	return ret
}

func (s StringSet) Hash() (uint64, error) {
	return hashstructure.Hash(s.ToSlice(), hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
}

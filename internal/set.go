package internal

import "sort"

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
	for _, str := range i {
		s[str] = struct{}{}
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

func (s StringSet) Equals(o StringSet) bool {
	if len(s) != len(o) {
		return false
	}
	for k := range s {
		if !o.Contains(k) {
			return false
		}
	}
	return true
}

func (s StringSet) Empty() bool {
	return len(s) < 1
}

package internal

import (
	"fmt"
	"sort"
)

// Set represents a generic set type.
type Set[T comparable] map[T]struct{}

// NewSet creates a new empty Set.
func NewSet[T comparable](start ...T) Set[T] {
	ret := make(Set[T])
	for _, v := range start {
		ret.Add(v)
	}
	return ret
}

// Add adds elements to the set.
func (s Set[T]) Add(elements ...T) {
	for _, e := range elements {
		s[e] = struct{}{}
	}
}

// Remove removes an element from the set.
func (s Set[T]) Remove(element T) {
	delete(s, element)
}

// Contains checks if an element is in the set.
func (s Set[T]) Contains(element T) bool {
	_, ok := s[element]
	return ok
}

// ToSlice returns a sorted slice of elements in the set.
func (s Set[T]) ToSlice() []T {
	ret := make([]T, len(s))
	idx := 0
	for v := range s {
		ret[idx] = v
		idx++
	}
	sort.Slice(ret, func(i, j int) bool {
		return fmt.Sprintf("%v", ret[i]) < fmt.Sprintf("%v", ret[j])
	})
	return ret
}

// Equals checks if two sets are equal.
func (s Set[T]) Equals(o Set[T]) bool {
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

// Empty checks if the set is empty.
func (s Set[T]) Empty() bool {
	return len(s) == 0
}

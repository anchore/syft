package source

import (
	"github.com/mitchellh/hashstructure/v2"
	"sort"
)

type LocationSet struct {
	set map[Location]struct{}
}

func NewLocationSet(locations ...Location) (s LocationSet) {
	s.safeAccess()
	for _, l := range locations {
		s.Add(l)
	}

	return s
}

func (s *LocationSet) safeAccess() {
	if s.set == nil {
		s.set = make(map[Location]struct{})
	}
}

func (s *LocationSet) Add(locations ...Location) {
	s.safeAccess()
	for _, l := range locations {
		s.set[l] = struct{}{}
	}
}

func (s *LocationSet) Remove(locations ...Location) {
	s.safeAccess()
	for _, l := range locations {
		delete(s.set, l)
	}
}

func (s *LocationSet) Contains(l Location) bool {
	s.safeAccess()
	_, ok := s.set[l]
	return ok
}

func (s *LocationSet) ToSlice() []Location {
	if s == nil {
		return nil
	}
	locations := make([]Location, len(s.set))
	idx := 0
	for v := range s.set {
		locations[idx] = v
		idx++
	}
	sort.Sort(Locations(locations))
	return locations
}

func (s *LocationSet) CoordinateSet() CoordinateSet {
	if s == nil {
		return NewCoordinateSet()
	}
	set := NewCoordinateSet()
	for l := range s.set {
		set.Add(l.Coordinates)
	}
	return set
}

func (s *LocationSet) Hash() (uint64, error) {
	cs := s.CoordinateSet()
	return hashstructure.Hash(&cs, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
}

package source

import (
	"sort"

	"github.com/mitchellh/hashstructure/v2"
)

type LocationSet struct {
	set map[Location]struct{}
}

func NewLocationSet(locations ...Location) (s LocationSet) {
	for _, l := range locations {
		s.Add(l)
	}

	return s
}

func (s *LocationSet) Add(locations ...Location) {
	if s.set == nil {
		s.set = make(map[Location]struct{})
	}
	for _, l := range locations {
		s.set[l] = struct{}{}
	}
}

func (s LocationSet) Remove(locations ...Location) {
	if s.set == nil {
		return
	}
	for _, l := range locations {
		delete(s.set, l)
	}
}

func (s LocationSet) Contains(l Location) bool {
	if s.set == nil {
		return false
	}
	_, ok := s.set[l]
	return ok
}

func (s LocationSet) ToSlice() []Location {
	if s.set == nil {
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
	if s.set == nil {
		return NewCoordinateSet()
	}
	set := NewCoordinateSet()
	for l := range s.set {
		set.Add(l.Coordinates)
	}
	return set
}

func (s LocationSet) Hash() (uint64, error) {
	// access paths and filesystem IDs are not considered when hashing a location set, only the real paths
	return hashstructure.Hash(s.CoordinateSet().Paths(), hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
}

package source

import (
	"github.com/mitchellh/hashstructure/v2"
	"sort"
)

type CoordinateSet struct {
	set map[Coordinates]struct{}
}

func NewCoordinateSet(coordinates ...Coordinates) (s CoordinateSet) {
	s.safeAccess()
	for _, l := range coordinates {
		s.Add(l)
	}

	return s
}

func (s *CoordinateSet) safeAccess() {
	if s.set == nil {
		s.set = make(map[Coordinates]struct{})
	}
}

func (s *CoordinateSet) Add(coordinates ...Coordinates) {
	s.safeAccess()
	for _, l := range coordinates {
		s.set[l] = struct{}{}
	}
}

func (s *CoordinateSet) Remove(coordinates ...Coordinates) {
	s.safeAccess()
	for _, l := range coordinates {
		delete(s.set, l)
	}
}

func (s *CoordinateSet) Contains(l Coordinates) bool {
	s.safeAccess()
	_, ok := s.set[l]
	return ok
}

func (s *CoordinateSet) ToSlice() []Coordinates {
	if s == nil {
		return nil
	}
	coordinates := make([]Coordinates, len(s.set))
	idx := 0
	for v := range s.set {
		coordinates[idx] = v
		idx++
	}
	sort.SliceStable(coordinates, func(i, j int) bool {
		if coordinates[i].RealPath == coordinates[j].RealPath {
			return coordinates[i].FileSystemID < coordinates[j].FileSystemID
		}
		return coordinates[i].RealPath < coordinates[j].RealPath
	})
	return coordinates
}

func (s *CoordinateSet) Hash() (uint64, error) {
	s.safeAccess()
	coordinates := s.ToSlice()
	for i, _ := range coordinates {
		// don't consider the filesystem when hashing the location, allowing us to deduplicate location.
		coordinates[i].FileSystemID = ""
	}
	return hashstructure.Hash(coordinates, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
}

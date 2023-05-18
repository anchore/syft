package file

import (
	"sort"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/syft/internal/log"
)

type LocationSet struct {
	set map[LocationData]LocationMetadata
}

func NewLocationSet(locations ...Location) (s LocationSet) {
	for _, l := range locations {
		s.Add(l)
	}

	return s
}

func (s *LocationSet) Add(locations ...Location) {
	if s.set == nil {
		s.set = make(map[LocationData]LocationMetadata)
	}
	for _, l := range locations {
		if m, ok := s.set[l.LocationData]; ok {
			err := m.merge(l.LocationMetadata)
			if err != nil {
				log.Debugf("partial merge of location metadata: %+v", err)
			}
			s.set[l.LocationData] = m
		} else {
			s.set[l.LocationData] = l.LocationMetadata
		}
	}
}

func (s LocationSet) Remove(locations ...Location) {
	if s.set == nil {
		return
	}
	for _, l := range locations {
		delete(s.set, l.LocationData)
	}
}

func (s LocationSet) Contains(l Location) bool {
	if s.set == nil {
		return false
	}
	_, ok := s.set[l.LocationData]
	return ok
}

func (s LocationSet) ToSlice() []Location {
	if s.set == nil {
		return nil
	}
	locations := make([]Location, len(s.set))
	idx := 0
	for dir := range s.set {
		locations[idx] = Location{
			LocationData:     dir,
			LocationMetadata: s.set[dir],
		}
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

func (s *LocationSet) Empty() bool {
	if s.set == nil {
		return true
	}
	return len(s.set) == 0
}

func (s LocationSet) Hash() (uint64, error) {
	// access paths and filesystem IDs are not considered when hashing a location set, only the real paths
	return hashstructure.Hash(s.CoordinateSet().Paths(), hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
}

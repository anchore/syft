package source

import "sort"

type LocationSet map[Location]struct{}

func NewLocationSet(locations ...Location) LocationSet {
	set := make(LocationSet)
	for _, l := range locations {
		set.Add(l)
	}

	return set
}

func (s LocationSet) Add(l Location) {
	s[l] = struct{}{}
}

func (s LocationSet) Remove(l Location) {
	delete(s, l)
}

func (s LocationSet) Contains(l Location) bool {
	_, ok := s[l]
	return ok
}

func (s LocationSet) ToSlice() []Location {
	locations := make([]Location, len(s))
	idx := 0
	for v := range s {
		locations[idx] = v
		idx++
	}
	sort.Sort(Locations(locations))
	return locations
}

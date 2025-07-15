package file

import (
	"sort"

	"github.com/gohugoio/hashstructure"
	"github.com/scylladb/go-set/strset"
)

type CoordinateSet struct {
	set map[Coordinates]struct{}
}

func NewCoordinateSet(coordinates ...Coordinates) (s CoordinateSet) {
	for _, l := range coordinates {
		s.Add(l)
	}

	return s
}

func (s *CoordinateSet) Add(coordinates ...Coordinates) {
	if s.set == nil {
		s.set = make(map[Coordinates]struct{})
	}
	for _, l := range coordinates {
		s.set[l] = struct{}{}
	}
}

func (s CoordinateSet) Remove(coordinates ...Coordinates) {
	if s.set == nil {
		return
	}
	for _, l := range coordinates {
		delete(s.set, l)
	}
}

func (s CoordinateSet) Contains(l Coordinates) bool {
	if s.set == nil {
		return false
	}
	_, ok := s.set[l]
	return ok
}

func (s CoordinateSet) Paths() []string {
	if s.set == nil {
		return nil
	}

	paths := strset.New()
	for _, c := range s.ToSlice() {
		paths.Add(c.RealPath)
	}
	pathSlice := paths.List()
	sort.Strings(pathSlice)
	return pathSlice
}

func (s CoordinateSet) ToSlice(sorters ...func(a, b Coordinates) int) []Coordinates {
	coordinates := s.ToUnorderedSlice()

	var sorted bool
	for _, sorter := range sorters {
		if sorter == nil {
			continue
		}
		sort.Slice(coordinates, func(i, j int) bool {
			return sorter(coordinates[i], coordinates[j]) < 0
		})
		sorted = true
		break
	}

	if !sorted {
		sort.SliceStable(coordinates, func(i, j int) bool {
			if coordinates[i].FileSystemID == coordinates[j].FileSystemID {
				return coordinates[i].RealPath < coordinates[j].RealPath
			}
			return coordinates[i].FileSystemID < coordinates[j].FileSystemID
		})
	}

	return coordinates
}

func (s CoordinateSet) ToUnorderedSlice() []Coordinates {
	if s.set == nil {
		return nil
	}
	coordinates := make([]Coordinates, len(s.set))
	idx := 0
	for v := range s.set {
		coordinates[idx] = v
		idx++
	}
	return coordinates
}

func (s CoordinateSet) Hash() (uint64, error) {
	return hashstructure.Hash(s.ToSlice(), &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
}

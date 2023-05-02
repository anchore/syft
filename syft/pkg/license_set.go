package pkg

import (
	"sort"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/syft/syft/license"
)

type setKey struct {
	expression string
	value      string
	t          license.Type
}

func newSetKey(l License) setKey {
	return setKey{expression: l.SPDXExpression, value: l.Value, t: l.Type}
}

type LicenseSet struct {
	set map[setKey]*License
}

func NewLicenseSet(licenses ...License) (s LicenseSet) {
	for _, l := range licenses {
		s.Add(l)
	}

	return s
}

func merge(update *License, other License) {
	update.Location.Add(other.Location.ToSlice()...)
	update.URL.Add(other.URL.ToSlice()...)
}

func (s *LicenseSet) Add(licenses ...License) {
	if s.set == nil {
		s.set = make(map[setKey]*License)
	}
	for _, l := range licenses {
		l := l
		if v, ok := s.set[newSetKey(l)]; ok {
			// already exists, update the location and update the url
			merge(v, l)
			continue
		}
		s.set[newSetKey(l)] = &l
	}
}

func (s LicenseSet) Remove(licenses ...License) {
	if s.set == nil {
		return
	}
	for _, l := range licenses {
		// remove the license from the specific index already found
		id := newSetKey(l)
		delete(s.set, id)
	}
}

func (s LicenseSet) Contains(l License) bool {
	if s.set == nil {
		return false
	}
	_, ok := s.set[newSetKey(l)]
	return ok
}

func (s LicenseSet) ToSlice() []License {
	licenses := make([]License, 0)
	if s.set == nil {
		return licenses
	}
	for _, v := range s.set {
		licenses = append(licenses, *v)
	}
	sort.Sort(Licenses(licenses))
	return licenses
}

func (s LicenseSet) Hash() (uint64, error) {
	// access paths and filesystem IDs are not considered when hashing a license set, only the real paths
	return hashstructure.Hash(s.ToSlice(), hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
}

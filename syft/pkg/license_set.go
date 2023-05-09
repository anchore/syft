package pkg

import (
	"fmt"
	"sort"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/syft/internal/log"
)

type LicenseSet struct {
	set map[uint64]License
}

func NewLicenseSet(licenses ...License) (s LicenseSet) {
	for _, l := range licenses {
		s.Add(l)
	}

	return s
}

func (s *LicenseSet) get(license License) (id uint64, merged bool, err error) {
	id, err = license.Hash()
	if err != nil {
		return 0, false, fmt.Errorf("could not get the hash for a license: %w", err)
	}

	v, ok := s.set[id]
	if !ok {
		// doesn't exist safe to add
		return id, false, nil
	}

	// we got the same id so we want to merge the URL OR Location data
	// URL/Location are not considered when taking the Hash
	m, err := v.Merge(license)
	if err != nil {
		return 0, false, fmt.Errorf("could not merge license into map: %w", err)
	}
	s.set[id] = *m

	return id, true, nil
}

func (s *LicenseSet) Add(licenses ...License) {
	if s.set == nil {
		s.set = make(map[uint64]License)
	}
	for _, l := range licenses {
		if id, merged, err := s.get(l); err == nil && !merged {
			// doesn't exist, add it
			s.set[id] = l
		} else if err != nil {
			log.Trace("license set failed to add license %#v: %+v", l, err)
		} else {
			log.Trace("merged licenses")
		}
	}
}

func (s LicenseSet) ToSlice() []License {
	if s.set == nil {
		return nil
	}
	var licenses []License
	for _, v := range s.set {
		licenses = append(licenses, v)
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

func (s LicenseSet) Empty() bool {
	return len(s.set) < 1
}

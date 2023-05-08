package pkg

import (
	"fmt"
	"sort"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/syft/internal/log"
)

type LicenseSet struct {
	set map[uint64]Licenses
}

func NewLicenseSet(licenses ...License) (s LicenseSet) {
	for _, l := range licenses {
		s.Add(l)
	}

	return s
}

func (s *LicenseSet) get(license License) (uint64, *License, error) {
	id, err := license.Hash()
	if err != nil {
		return 0, nil, fmt.Errorf("could not get the hash for a license: %w", err)
	}

	licenses, ok := s.set[id]
	if !ok {
		return id, nil, nil
	}

	if license.Location.Empty() {
		switch len(licenses) {
		case 0:
			return id, nil, nil
		case 1:
			return id, &licenses[0], nil
		default:
			log.Debugf("license set contains multiple licenses with the same hash (when there is no location): %#v returns %#v", license, licenses)
			// we don't know what the right answer is
			return id, nil, nil
		}
	}

	// check if license being added has duplicate location
	for _, l := range licenses {
		// duplicate hash
		licenseHash, err := license.Location.Hash()
		if err != nil {
			log.Trace("could not get location hash for licenses %v: %w", license, err)
			continue
		}
		compareHash, err := l.Location.Hash()
		if err != nil {
			log.Trace("could not get location hash for licenses %v: %w", license, err)
			continue
		}

		if licenseHash == compareHash {
			// we still need to check the file system ID
			compareSet := l.Location.CoordinateSet().ToSlice()
			licenseSet := license.Location.CoordinateSet().ToSlice()
			if len(compareSet) != len(licenseSet) {
				return 0, nil, fmt.Errorf("duplicate licenses trying to be added")
			}
			for i, v := range compareSet {
				if licenseSet[i] == v {
					return 0, nil, fmt.Errorf("duplicate licenses trying to be added")
				}
			}
		}
	}

	return id, nil, nil
}

func (s *LicenseSet) Add(licenses ...License) {
	if s.set == nil {
		s.set = make(map[uint64]Licenses)
	}
	for _, l := range licenses {
		if id, v, err := s.get(l); v == nil && err == nil {
			// doesn't exist, add it
			s.set[id] = append(s.set[id], l)
		} else if err != nil {
			log.Debugf("license set failed to add license %#v: %+v", l, err)
		}
	}
}

func (s LicenseSet) Remove(licenses ...License) {
	if s.set == nil {
		return
	}
	for _, l := range licenses {
		id, v, err := s.get(l)
		if err != nil {
			log.Debugf("license set failed to remove license %#v: %+v", l, err)
		}
		if v == nil {
			continue
		}
		// remove the license from the specific index already found
		s.set[id] = append(s.set[id][:0], s.set[id][0+1:]...)
	}
}

func (s LicenseSet) Contains(l License) bool {
	if s.set == nil {
		return false
	}
	_, v, err := s.get(l)
	return v != nil && err == nil
}

func (s LicenseSet) ToSlice() []License {
	if s.set == nil {
		return nil
	}
	var licenses []License
	for _, v := range s.set {
		licenses = append(licenses, v...)
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

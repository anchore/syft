package pkg

import (
	"fmt"
	"github.com/anchore/syft/internal/log"
	"github.com/mitchellh/hashstructure/v2"
	"sort"
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

func (s *LicenseSet) get(license License) (uint64, int, *License, error) {
	id, err := license.Hash()
	if err != nil {
		return 0, 0, nil, fmt.Errorf("could not get the hash for a license: %w", err)
	}
	licenses, ok := s.set[id]
	if !ok {
		return id, 0, nil, nil
	}

	if license.Location == nil {
		switch len(licenses) {
		case 0:
			return id, 0, nil, nil
		case 1:
			return id, 0, &licenses[0], nil
		default:
			log.Debugf("license set contains multiple licenses with the same hash (when there is no location): %#v returns %#v", license, licenses)
			// we don't know what the right answer is
			return id, 0, nil, nil
		}
	}

	// I'm only hitting this if the FS id is different, since that's the only reason today that you can have
	// the same hash ID but different information on the license
	for idx, l := range licenses {
		if l.Location.FileSystemID == license.Location.FileSystemID {
			return id, idx, &licenses[idx], nil
		}
	}

	return id, 0, nil, nil
}

func (s *LicenseSet) Add(licenses ...License) {
	if s.set == nil {
		s.set = make(map[uint64]Licenses)
	}
	for _, l := range licenses {
		if id, _, v, err := s.get(l); v == nil && err == nil {
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
		id, idx, v, err := s.get(l)
		if err != nil {
			log.Debugf("license set failed to remove license %#v: %+v", l, err)
		}
		if v == nil {
			continue
		}
		// remove the license from the specific index already found
		s.set[id] = append(s.set[id][:idx], s.set[id][idx+1:]...)
	}
}

func (s LicenseSet) Contains(l License) bool {
	if s.set == nil {
		return false
	}
	_, _, v, err := s.get(l)
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

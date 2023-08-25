package pkg

import (
	"fmt"
	"sort"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
)

type LicenseSet struct {
	set map[artifact.ID]License
}

func NewLicenseSet(licenses ...License) (s LicenseSet) {
	for _, l := range licenses {
		s.Add(l)
	}

	return s
}

func (s *LicenseSet) addToExisting(license License) (id artifact.ID, merged bool, err error) {
	id, err = artifact.IDByHash(license)
	if err != nil {
		return id, false, fmt.Errorf("could not get the hash for a license: %w", err)
	}

	v, ok := s.set[id]
	if !ok {
		// doesn't exist safe to add
		return id, false, nil
	}

	// we got the same id; we want to merge the URLs and Location data
	// URLs/Location are not considered when taking the Hash
	m, err := v.Merge(license)
	if err != nil {
		return id, false, fmt.Errorf("could not merge license into map: %w", err)
	}
	s.set[id] = *m

	return id, true, nil
}

func (s *LicenseSet) Add(licenses ...License) {
	if s.set == nil {
		s.set = make(map[artifact.ID]License)
	}
	for _, l := range licenses {
		// we only want to add licenses that have a value
		// note, this check should be moved to the license constructor in the future
		if l.Value != "" {
			if id, merged, err := s.addToExisting(l); err == nil && !merged {
				// doesn't exist, add it
				s.set[id] = l
			} else if err != nil {
				log.Trace("license set failed to add license %#v: %+v", l, err)
			}
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

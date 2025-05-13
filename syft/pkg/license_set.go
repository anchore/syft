package pkg

import (
	"fmt"
	"sort"

	"github.com/gohugoio/hashstructure"

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
		// we only want to add licenses that are not empty
		if l.Empty() {
			continue
		}
		// note, this check should be moved to the license constructor in the future
		if id, merged, err := s.addToExisting(l); err == nil && !merged {
			// doesn't exist, add it
			s.set[id] = l
		} else if err != nil {
			log.WithFields("error", err, "license", l).Trace("failed to add license to license set")
		}
	}
}

func (s LicenseSet) ToSlice(sorters ...func(a, b License) int) []License {
	licenses := s.ToUnorderedSlice()

	var sorted bool
	for _, sorter := range sorters {
		if sorter == nil {
			continue
		}
		sort.Slice(licenses, func(i, j int) bool {
			return sorter(licenses[i], licenses[j]) < 0
		})
		sorted = true
		break
	}

	if !sorted {
		sort.Sort(Licenses(licenses))
	}

	return licenses
}

func (s LicenseSet) ToUnorderedSlice() []License {
	if s.set == nil {
		return nil
	}
	licenses := make([]License, len(s.set))
	idx := 0
	for _, v := range s.set {
		licenses[idx] = v
		idx++
	}
	return licenses
}

func (s LicenseSet) Hash() (uint64, error) {
	// access paths and filesystem IDs are not considered when hashing a license set, only the real paths
	return hashstructure.Hash(s.ToSlice(), &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
}

func (s LicenseSet) Empty() bool {
	return len(s.set) < 1
}

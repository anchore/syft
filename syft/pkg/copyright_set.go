//nolint:dupl
package pkg

import (
	"fmt"
	"sort"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
)

type CopyrightsSet struct {
	set map[artifact.ID]Copyright
}

func NewCopyrightSet(copyrights ...Copyright) (c CopyrightsSet) {
	for _, l := range copyrights {
		c.Add(l)
	}

	return c
}

func (c *CopyrightsSet) addToExisting(copyright Copyright) (id artifact.ID, merged bool, err error) {
	id, err = artifact.IDByHash(copyright)
	if err != nil {
		return id, false, fmt.Errorf("could not get the hash for a copyright: %w", err)
	}

	v, ok := c.set[id]
	if !ok {
		// doesn't exist safe to add
		return id, false, nil
	}

	// we got the same id; we want to merge the URLs and Location data
	// URLs/Location are not considered when taking the Hash
	m, err := v.Merge(copyright)
	if err != nil {
		return id, false, fmt.Errorf("could not merge license into map: %w", err)
	}
	c.set[id] = *m

	return id, true, nil
}

func (c *CopyrightsSet) Add(copyrights ...Copyright) {
	if c.set == nil {
		c.set = make(map[artifact.ID]Copyright)
	}
	for _, l := range copyrights {
		// we only want to add copyrights that have a value
		// note, this check should be moved to the license constructor in the future
		if l.Author != "" {
			if id, merged, err := c.addToExisting(l); err == nil && !merged {
				// doesn't exist, add it
				c.set[id] = l
			} else if err != nil {
				log.Trace("copyright set failed to add copyright %#v: %+v", l, err)
			}
		}
	}
}

func (c CopyrightsSet) ToSlice() []Copyright {
	if c.set == nil {
		return nil
	}
	var copyrights []Copyright
	for _, v := range c.set {
		copyrights = append(copyrights, v)
	}
	sort.Sort(Copyrights(copyrights))
	return copyrights
}

func (c CopyrightsSet) Hash() (uint64, error) {
	// access paths and filesystem IDs are not considered when hashing a copyright set, only the real paths
	return hashstructure.Hash(c.ToSlice(), hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
}

func (c CopyrightsSet) Empty() bool {
	return len(c.set) < 1
}
